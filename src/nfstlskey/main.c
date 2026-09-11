/**
 * @file main.c
 * @brief Manage named x.509 client identities for NFS mTLS mounts
 *
 * @copyright
 * Copyright (c) 2026 Oracle and/or its affiliates.
 */

/*
 * ktls-utils is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <config.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <keyutils.h>
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#define NFSTLSKEY_KEY_TYPE	"user"
#define NFSTLSKEY_DESC_PREFIX	"nfs:x509:"
#define NFSTLSKEY_CERT_SUFFIX	":cert"
#define NFSTLSKEY_PRIVKEY_SUFFIX	":privkey"

/* Payloads are readable only through possession of the .nfs keyring. */
#define NFSTLSKEY_KEY_PERM	(KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_SEARCH)

struct nfstlskey_key_id {
	unsigned char data[64];
	size_t size;
};

struct nfstlskey_key_desc {
	char *buf;
	const char *type;
	uid_t uid;
	const char *description;
};

static const char *progname;

static void usage(void)
{
	fprintf(stderr,
		"usage: %s add <identity> --cert <file> --key <file>\n"
		"       %s list\n"
		"       %s remove <identity>\n"
		"       %s show <identity>\n"
		"       %s update <identity> --cert <file> --key <file>\n",
		progname, progname, progname, progname, progname);
}

/*
 * Colons and semicolons delimit a key description, commas delimit
 * mount options, and a non-printable would break the one identity
 * per line of list output.
 */
static bool nfstlskey_identity_valid(const char *identity)
{
	const char *p;

	if (identity[0] == '\0')
		return false;
	for (p = identity; *p != '\0'; p++)
		if (!isgraph((unsigned char)*p) ||
		    *p == ':' || *p == ';' || *p == ',')
			return false;
	return true;
}

static char *nfstlskey_description(const char *identity, const char *suffix)
{
	size_t len;
	char *desc;

	len = strlen(NFSTLSKEY_DESC_PREFIX) + strlen(identity) +
		strlen(suffix) + 1;
	desc = malloc(len);
	if (!desc)
		return NULL;
	snprintf(desc, len, "%s%s%s", NFSTLSKEY_DESC_PREFIX, identity, suffix);
	return desc;
}

/*
 * The kernel does not autoload a module to satisfy a key type
 * lookup, so an nfs_keyring request fails until nfs.ko is loaded.
 */
static bool nfstlskey_modprobe_nfs(void)
{
	int status;
	pid_t pid;

	pid = fork();
	if (pid < 0)
		return false;
	if (pid == 0) {
		execl("/sbin/modprobe", "modprobe", "-q", "nfs", (char *)NULL);
		_exit(127);
	}
	while (waitpid(pid, &status, 0) < 0)
		if (errno != EINTR)
			return false;
	return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* keyctl_describe answers "type;uid;gid;perm;description". */
static bool nfstlskey_describe(key_serial_t key,
			       struct nfstlskey_key_desc *kd)
{
	char *field, *end;

	if (keyctl_describe_alloc(key, &kd->buf) < 0)
		return false;

	kd->type = kd->buf;
	field = strchr(kd->buf, ';');
	if (!field)
		goto fail;
	*field++ = '\0';
	kd->uid = strtoul(field, &end, 10);
	if (end == field || *end != ';')
		goto fail;
	field = strchr(end + 1, ';');
	if (!field)
		goto fail;
	field = strchr(field + 1, ';');
	if (!field)
		goto fail;
	kd->description = field + 1;
	return true;

fail:
	free(kd->buf);
	return false;
}

/*
 * Backstop for the session keyring join in nfstlskey_get_keyring():
 * only a root-owned key of the expected type and description is
 * trusted.
 */
static bool nfstlskey_key_is(key_serial_t key, const char *type,
			     const char *description)
{
	struct nfstlskey_key_desc kd;
	bool match;

	if (!nfstlskey_describe(key, &kd))
		return false;
	match = strcmp(kd.type, type) == 0 && kd.uid == 0 &&
		(!description || strcmp(kd.description, description) == 0);
	free(kd.buf);
	return match;
}

/*
 * The nfs_keyring key type answers with the serial of the .nfs
 * keyring that belongs to the caller's network namespace. A kernel
 * without that type has a single .nfs keyring shared by every
 * namespace, which only a scan of /proc/keys can find. Linking the
 * keyring into the process keyring makes this process a possessor
 * of every key on it for as long as the process lives.
 */
static key_serial_t nfstlskey_get_keyring(void)
{
	key_serial_t key, keyring;
	void *payload;
	int saved_errno;
	long ret;

	/*
	 * request_key() searches the session keyring before the kernel
	 * instantiates a key of its own. An inherited session keyring
	 * is writable by the user who logged in, so a fresh one keeps
	 * a key that user planted from answering the request.
	 */
	if (keyctl_join_session_keyring(NULL) < 0) {
		fprintf(stderr, "%s: join session keyring: %s\n", progname,
			strerror(errno));
		return 0;
	}

	key = request_key("nfs_keyring", ".nfs", "", KEY_SPEC_THREAD_KEYRING);
	saved_errno = errno;
	if (key < 0 && saved_errno == ENOKEY && nfstlskey_modprobe_nfs()) {
		key = request_key("nfs_keyring", ".nfs", "",
				  KEY_SPEC_THREAD_KEYRING);
		saved_errno = errno;
	}
	if (key < 0 && saved_errno == ENOKEY) {
		keyring = find_key_by_type_and_desc("keyring", ".nfs", 0);
		if (keyring < 0) {
			fprintf(stderr, "%s: find .nfs keyring: %s\n",
				progname, strerror(errno));
			return 0;
		}
		fprintf(stderr, "%s: using the .nfs keyring shared by all network namespaces\n",
			progname);
		goto link;
	}
	if (key < 0) {
		fprintf(stderr, "%s: request nfs_keyring: %s\n", progname,
			strerror(saved_errno));
		return 0;
	}
	if (!nfstlskey_key_is(key, "nfs_keyring", ".nfs")) {
		fprintf(stderr, "%s: nfs_keyring key %d is not trusted\n",
			progname, key);
		return 0;
	}

	ret = keyctl_read_alloc(key, &payload);
	if (ret < 0) {
		fprintf(stderr, "%s: read nfs_keyring: %s\n", progname,
			strerror(errno));
		return 0;
	}
	keyring = (key_serial_t)strtol(payload, NULL, 10);
	free(payload);

link:
	if (!nfstlskey_key_is(keyring, "keyring", ".nfs")) {
		fprintf(stderr, "%s: keyring %d is not the .nfs keyring\n",
			progname, keyring);
		return 0;
	}

	if (keyctl_link(keyring, KEY_SPEC_PROCESS_KEYRING) < 0) {
		fprintf(stderr, "%s: link .nfs keyring: %s\n", progname,
			strerror(errno));
		return 0;
	}
	return keyring;
}

/*
 * Returns the serial of the matching key, zero when no such key
 * exists, or -1 after reporting any other search failure.
 */
static key_serial_t nfstlskey_search(key_serial_t keyring,
				     const char *identity, const char *suffix)
{
	key_serial_t key;
	char *desc;

	desc = nfstlskey_description(identity, suffix);
	if (!desc) {
		fprintf(stderr, "%s: %s\n", progname, strerror(ENOMEM));
		return -1;
	}
	key = keyctl_search(keyring, NFSTLSKEY_KEY_TYPE, desc, 0);
	if (key < 0 && errno == ENOKEY)
		key = 0;
	if (key < 0)
		fprintf(stderr, "%s: search %s: %s\n", progname, desc,
			strerror(errno));
	free(desc);
	return key;
}

/*
 * An identity exists when either of its keys does. Returns the
 * number of keys found, or -1 after a search failure.
 */
static int nfstlskey_find(key_serial_t keyring, const char *identity,
			  key_serial_t *cert_key, key_serial_t *privkey_key)
{
	*cert_key = nfstlskey_search(keyring, identity, NFSTLSKEY_CERT_SUFFIX);
	if (*cert_key < 0)
		return -1;
	*privkey_key = nfstlskey_search(keyring, identity,
					NFSTLSKEY_PRIVKEY_SUFFIX);
	if (*privkey_key < 0)
		return -1;
	return (*cert_key > 0) + (*privkey_key > 0);
}

static key_serial_t nfstlskey_add_key(key_serial_t keyring,
				      const char *identity, const char *suffix,
				      const gnutls_datum_t *der)
{
	key_serial_t key;
	char *desc;

	desc = nfstlskey_description(identity, suffix);
	if (!desc)
		return -1;
	key = add_key(NFSTLSKEY_KEY_TYPE, desc, der->data, der->size, keyring);
	free(desc);
	if (key < 0)
		return key;

	if (keyctl_setperm(key, NFSTLSKEY_KEY_PERM) < 0) {
		int saved = errno;

		if (keyctl_unlink(key, keyring) < 0)
			fprintf(stderr, "%s: remove key %d: %s\n", progname,
				key, strerror(errno));
		errno = saved;
		return -1;
	}
	return key;
}

/*
 * tlshd presents the one certificate it reads from the key, so a
 * file that carries a chain is refused rather than truncated.
 */
static bool nfstlskey_load_cert(const char *path, gnutls_datum_t *der,
				struct nfstlskey_key_id *id)
{
	gnutls_x509_crt_t *crts;
	unsigned int count, i;
	gnutls_datum_t pem;
	bool ok = false;
	int ret;

	ret = gnutls_load_file(path, &pem);
	if (ret != GNUTLS_E_SUCCESS)
		goto out;
	ret = gnutls_x509_crt_list_import2(&crts, &count, &pem,
					   GNUTLS_X509_FMT_PEM, 0);
	gnutls_free(pem.data);
	if (ret != GNUTLS_E_SUCCESS)
		goto out;

	if (count != 1) {
		fprintf(stderr, "%s: %s: holds %u certificates, expected one\n",
			progname, path, count);
		goto out_crts;
	}
	id->size = sizeof(id->data);
	ret = gnutls_x509_crt_get_key_id(crts[0], 0, id->data, &id->size);
	if (ret != GNUTLS_E_SUCCESS)
		goto out_crts;
	ret = gnutls_x509_crt_export2(crts[0], GNUTLS_X509_FMT_DER, der);
	if (ret != GNUTLS_E_SUCCESS)
		goto out_crts;
	ok = true;

out_crts:
	for (i = 0; i < count; i++)
		gnutls_x509_crt_deinit(crts[i]);
	gnutls_free(crts);
out:
	if (ret != GNUTLS_E_SUCCESS)
		fprintf(stderr, "%s: %s: %s\n", progname, path,
			gnutls_strerror(ret));
	return ok;
}

static bool nfstlskey_load_privkey(const char *path, gnutls_datum_t *der,
				   struct nfstlskey_key_id *id)
{
	gnutls_x509_privkey_t key;
	gnutls_datum_t pem;
	int ret;

	ret = gnutls_load_file(path, &pem);
	if (ret != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "%s: %s: %s\n", progname, path,
			gnutls_strerror(ret));
		return false;
	}

	ret = gnutls_x509_privkey_init(&key);
	if (ret != GNUTLS_E_SUCCESS)
		goto out_pem;
	ret = gnutls_x509_privkey_import2(key, &pem, GNUTLS_X509_FMT_PEM,
					  NULL, 0);
	if (ret != GNUTLS_E_SUCCESS)
		goto out_key;
	id->size = sizeof(id->data);
	ret = gnutls_x509_privkey_get_key_id(key, 0, id->data, &id->size);
	if (ret != GNUTLS_E_SUCCESS)
		goto out_key;
	ret = gnutls_x509_privkey_export2(key, GNUTLS_X509_FMT_DER, der);

out_key:
	gnutls_x509_privkey_deinit(key);
out_pem:
	gnutls_memset(pem.data, 0, pem.size);
	gnutls_free(pem.data);
	if (ret != GNUTLS_E_SUCCESS)
		fprintf(stderr, "%s: %s: %s\n", progname, path,
			gnutls_strerror(ret));
	return ret == GNUTLS_E_SUCCESS;
}

static void nfstlskey_free_pair(gnutls_datum_t *cert, gnutls_datum_t *privkey)
{
	gnutls_memset(privkey->data, 0, privkey->size);
	gnutls_free(privkey->data);
	gnutls_free(cert->data);
}

static bool nfstlskey_load_pair(const char *cert_path, const char *key_path,
				gnutls_datum_t *cert, gnutls_datum_t *privkey)
{
	struct nfstlskey_key_id cert_id, privkey_id;

	if (!nfstlskey_load_cert(cert_path, cert, &cert_id))
		return false;
	if (!nfstlskey_load_privkey(key_path, privkey, &privkey_id)) {
		gnutls_free(cert->data);
		return false;
	}
	if (cert_id.size != privkey_id.size ||
	    memcmp(cert_id.data, privkey_id.data, cert_id.size) != 0) {
		fprintf(stderr, "%s: %s does not match the public key in %s\n",
			progname, key_path, cert_path);
		nfstlskey_free_pair(cert, privkey);
		return false;
	}
	return true;
}

static bool nfstlskey_parse_pair_args(int argc, char **argv,
				      const char **identity,
				      const char **cert_path,
				      const char **key_path)
{
	static const struct option longopts[] = {
		{ "cert",	required_argument,	NULL,	'c' },
		{ "key",	required_argument,	NULL,	'k' },
		{ NULL,		0,			NULL,	0 },
	};
	int c;

	if (argc < 3) {
		usage();
		return false;
	}
	*identity = argv[2];
	*cert_path = NULL;
	*key_path = NULL;

	/* argv[0] stays the program name so getopt diagnostics name it. */
	optind = 3;
	while ((c = getopt_long(argc, argv, "c:k:", longopts, NULL)) != -1) {
		switch (c) {
		case 'c':
			*cert_path = optarg;
			break;
		case 'k':
			*key_path = optarg;
			break;
		default:
			usage();
			return false;
		}
	}
	if (optind != argc || !*cert_path || !*key_path) {
		usage();
		return false;
	}
	if (!nfstlskey_identity_valid(*identity)) {
		fprintf(stderr, "%s: invalid identity '%s'\n", progname,
			*identity);
		return false;
	}
	return true;
}

static int nfstlskey_add(int argc, char **argv)
{
	const char *identity, *cert_path, *key_path;
	gnutls_datum_t cert, privkey;
	key_serial_t keyring, cert_key, privkey_key;
	int ret = EXIT_FAILURE;

	if (!nfstlskey_parse_pair_args(argc, argv, &identity, &cert_path,
				       &key_path))
		return EXIT_FAILURE;

	keyring = nfstlskey_get_keyring();
	if (!keyring)
		return EXIT_FAILURE;
	switch (nfstlskey_find(keyring, identity, &cert_key, &privkey_key)) {
	case 0:
		break;
	case -1:
		return EXIT_FAILURE;
	default:
		fprintf(stderr, "%s: identity '%s' already exists\n",
			progname, identity);
		return EXIT_FAILURE;
	}

	if (!nfstlskey_load_pair(cert_path, key_path, &cert, &privkey))
		return EXIT_FAILURE;

	cert_key = nfstlskey_add_key(keyring, identity, NFSTLSKEY_CERT_SUFFIX,
				     &cert);
	if (cert_key < 0) {
		fprintf(stderr, "%s: add certificate: %s\n", progname,
			strerror(errno));
		goto out;
	}
	privkey_key = nfstlskey_add_key(keyring, identity,
					NFSTLSKEY_PRIVKEY_SUFFIX, &privkey);
	if (privkey_key < 0) {
		fprintf(stderr, "%s: add private key: %s\n", progname,
			strerror(errno));
		if (keyctl_unlink(cert_key, keyring) < 0)
			fprintf(stderr, "%s: remove certificate: %s\n",
				progname, strerror(errno));
		goto out;
	}

	printf("%s: cert_serial=%d privkey_serial=%d\n", identity,
	       cert_key, privkey_key);
	ret = EXIT_SUCCESS;

out:
	nfstlskey_free_pair(&cert, &privkey);
	return ret;
}

/*
 * Mounts hold the serials, and tlshd reads each key's payload at
 * every handshake, so replacing the payloads in place rotates the
 * key material without a remount.
 */
static int nfstlskey_update(int argc, char **argv)
{
	const char *identity, *cert_path, *key_path;
	gnutls_datum_t cert, privkey;
	key_serial_t keyring, cert_key, privkey_key;
	int ret = EXIT_FAILURE;

	if (!nfstlskey_parse_pair_args(argc, argv, &identity, &cert_path,
				       &key_path))
		return EXIT_FAILURE;

	keyring = nfstlskey_get_keyring();
	if (!keyring)
		return EXIT_FAILURE;
	switch (nfstlskey_find(keyring, identity, &cert_key, &privkey_key)) {
	case 2:
		break;
	case -1:
		return EXIT_FAILURE;
	case 0:
		fprintf(stderr, "%s: identity '%s' not found\n", progname,
			identity);
		return EXIT_FAILURE;
	default:
		fprintf(stderr, "%s: identity '%s' is incomplete; remove it and add it again\n",
			progname, identity);
		return EXIT_FAILURE;
	}

	if (!nfstlskey_load_pair(cert_path, key_path, &cert, &privkey))
		return EXIT_FAILURE;

	if (keyctl_update(cert_key, cert.data, cert.size) < 0) {
		fprintf(stderr, "%s: update certificate: %s\n", progname,
			strerror(errno));
		goto out;
	}
	if (keyctl_update(privkey_key, privkey.data, privkey.size) < 0) {
		fprintf(stderr, "%s: update private key: %s\n", progname,
			strerror(errno));
		goto out;
	}

	printf("%s: cert_serial=%d privkey_serial=%d\n", identity,
	       cert_key, privkey_key);
	ret = EXIT_SUCCESS;

out:
	nfstlskey_free_pair(&cert, &privkey);
	return ret;
}

/*
 * An identity that has lost its certificate key is listed by its
 * private key so that it can still be removed.
 */
static int nfstlskey_list(int argc, char **argv)
{
	key_serial_t keyring, *keys;
	size_t prefix_len, cert_len, privkey_len;
	long count, i;
	int ret = EXIT_SUCCESS;

	(void)argv;
	if (argc != 2) {
		usage();
		return EXIT_FAILURE;
	}

	keyring = nfstlskey_get_keyring();
	if (!keyring)
		return EXIT_FAILURE;

	count = keyctl_read_alloc(keyring, (void **)&keys);
	if (count < 0) {
		fprintf(stderr, "%s: read .nfs keyring: %s\n", progname,
			strerror(errno));
		return EXIT_FAILURE;
	}
	count /= sizeof(*keys);

	prefix_len = strlen(NFSTLSKEY_DESC_PREFIX);
	cert_len = strlen(NFSTLSKEY_CERT_SUFFIX);
	privkey_len = strlen(NFSTLSKEY_PRIVKEY_SUFFIX);
	for (i = 0; i < count && ret == EXIT_SUCCESS; i++) {
		struct nfstlskey_key_desc kd;
		char *identity;
		size_t len;

		if (!nfstlskey_describe(keys[i], &kd))
			continue;
		len = strlen(kd.description);
		if (strcmp(kd.type, NFSTLSKEY_KEY_TYPE) != 0 ||
		    len <= prefix_len ||
		    strncmp(kd.description, NFSTLSKEY_DESC_PREFIX,
			    prefix_len) != 0)
			goto next;
		identity = (char *)kd.description + prefix_len;

		if (len > prefix_len + cert_len &&
		    strcmp(kd.description + len - cert_len,
			   NFSTLSKEY_CERT_SUFFIX) == 0) {
			identity[len - prefix_len - cert_len] = '\0';
			printf("%s\n", identity);
		} else if (len > prefix_len + privkey_len &&
			   strcmp(kd.description + len - privkey_len,
				  NFSTLSKEY_PRIVKEY_SUFFIX) == 0) {
			key_serial_t cert_key;

			identity[len - prefix_len - privkey_len] = '\0';
			cert_key = nfstlskey_search(keyring, identity,
						    NFSTLSKEY_CERT_SUFFIX);
			if (cert_key < 0)
				ret = EXIT_FAILURE;
			else if (cert_key == 0)
				printf("%s\n", identity);
		}
next:
		free(kd.buf);
	}
	free(keys);
	return ret;
}

static int nfstlskey_remove(int argc, char **argv)
{
	key_serial_t keyring, cert_key, privkey_key;
	const char *identity;
	int ret = EXIT_SUCCESS;

	if (argc != 3) {
		usage();
		return EXIT_FAILURE;
	}
	identity = argv[2];

	keyring = nfstlskey_get_keyring();
	if (!keyring)
		return EXIT_FAILURE;
	switch (nfstlskey_find(keyring, identity, &cert_key, &privkey_key)) {
	case -1:
		return EXIT_FAILURE;
	case 0:
		fprintf(stderr, "%s: identity '%s' not found\n", progname,
			identity);
		return EXIT_FAILURE;
	}

	if (cert_key > 0 && keyctl_unlink(cert_key, keyring) < 0) {
		fprintf(stderr, "%s: remove certificate: %s\n", progname,
			strerror(errno));
		ret = EXIT_FAILURE;
	}
	if (privkey_key > 0 && keyctl_unlink(privkey_key, keyring) < 0) {
		fprintf(stderr, "%s: remove private key: %s\n", progname,
			strerror(errno));
		ret = EXIT_FAILURE;
	}
	return ret;
}

static int nfstlskey_show(int argc, char **argv)
{
	key_serial_t keyring, cert_key, privkey_key;
	const char *identity;

	if (argc != 3) {
		usage();
		return EXIT_FAILURE;
	}
	identity = argv[2];

	keyring = nfstlskey_get_keyring();
	if (!keyring)
		return EXIT_FAILURE;
	switch (nfstlskey_find(keyring, identity, &cert_key, &privkey_key)) {
	case 2:
		break;
	case -1:
		return EXIT_FAILURE;
	case 0:
		fprintf(stderr, "%s: identity '%s' not found\n", progname,
			identity);
		return EXIT_FAILURE;
	default:
		fprintf(stderr, "%s: identity '%s' is incomplete; remove it and add it again\n",
			progname, identity);
		return EXIT_FAILURE;
	}

	printf("cert_serial=%d,privkey_serial=%d\n", cert_key, privkey_key);
	return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
	const char *cmd;
	int ret;

	progname = argv[0];
	if (argc < 2) {
		usage();
		return EXIT_FAILURE;
	}
	cmd = argv[1];

	ret = gnutls_global_init();
	if (ret != GNUTLS_E_SUCCESS) {
		fprintf(stderr, "%s: %s\n", progname, gnutls_strerror(ret));
		return EXIT_FAILURE;
	}

	if (strcmp(cmd, "add") == 0)
		ret = nfstlskey_add(argc, argv);
	else if (strcmp(cmd, "list") == 0)
		ret = nfstlskey_list(argc, argv);
	else if (strcmp(cmd, "remove") == 0)
		ret = nfstlskey_remove(argc, argv);
	else if (strcmp(cmd, "show") == 0)
		ret = nfstlskey_show(argc, argv);
	else if (strcmp(cmd, "update") == 0)
		ret = nfstlskey_update(argc, argv);
	else {
		usage();
		ret = EXIT_FAILURE;
	}

	gnutls_global_deinit();
	return ret;
}
