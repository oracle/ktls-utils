# Contributing Guidelines

Thank you for your interest in contributing to our project!
Whether it's a bug report, new feature, correction, or additional
documentation, we greatly value feedback and contributions from
the open source community.

Please read through this document before submitting an issue or pull
request to ensure we have all the necessary information to
effectively respond to your bug report or contribution.

A ktls-utils developer mailing list is available. See
[lists.linux.dev](https://subspace.kernel.org/lists.linux.dev.html)
for links to subscribe to <kernel-tls-handshake@lists.linux.dev> or
to access archived threads.

## Opening issues

We welcome you to use the GitHub
[ktls-utils issue tracker](https://github.com/oracle/ktls-utils/issues)
to report bugs or suggest features.

When filing an issue, please check existing open or recently closed
issues to make sure somebody else hasn't already reported the
issue. Please try to include as much information as you can.
Details like these are incredibly useful:

* A reproducible test case or series of steps
* The version of our code being used
* Any modifications you've made relevant to the bug
* Anything unusual about your environment or deployment

If you think you've found a security
vulnerability, do not raise a GitHub issue and follow the instructions in our
[security policy](./SECURITY.md).

## Contributing code

We welcome your code contributions. Code contributions must have a developer 
certificate of origin. Acknowledge the Developer Certificate of Origin by 
including the following text with your commit message.

```text
Signed-off-by: Your Name <you@example.org>
```

This can be automatically added to pull requests by committing with `--sign-off`
or `-s`, e.g.

```text
git commit --signoff
```

Review the [Developer Certificate of Origin][DCO].

## Pull request process

To contribute code, please post patches (not attachments) to
[lists.linux.dev](https://subspace.kernel.org/lists.linux.dev.html).
Sending email enables the community, which includes some who do not
have GitHub accounts, to participate in review.

GitHub pull requests also work. To send us a pull request:

1. Fork the oracle/ktls-utils repository.
2. Modify the source. Focus on the specific change you are
   contributing. If you also reformat all the code, it will
   be hard for us to review on your change.
3. Ensure local tests pass.
4. Commit to your fork using concise commit messages.
5. Send us a pull request, answering any default questions in the pull
   request interface.
6. Pay attention to any automated CI failures reported in the pull
   request and stay involved in the conversation.

GitHub provides additional document on
[forking a repository](https://help.github.com/articles/fork-a-repo/) and
[creating a pull request](https://help.github.com/articles/creating-a-pull-request/).

## Licensing

See the [COPYING](COPYING) file for our project's licensing. We will
ask you to confirm the licensing of your contribution.

## Code of conduct

Follow the [Golden Rule](https://en.wikipedia.org/wiki/Golden_Rule). If you'd
like more specific guidelines, see the [Contributor Covenant Code of Conduct][COC].

[DCO]: https://developercertificate.org/
[COC]: https://www.contributor-covenant.org/version/1/4/code-of-conduct/
