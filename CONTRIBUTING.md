# Contributing to LightFTP

## Project Philosophy

This FTP server is designed to work with the majority of real-world FTP clients. Many popular FTP clients are not fully RFC-compliant, and prioritizing strict RFC compliance over real-world compatibility will break support for these clients.

**Our priority: Real-world client compatibility > Theoretical RFC compliance**

## Before Submitting Pull Requests

Please ensure your contribution meets the following requirements:

1. **Code must compile without errors**
   - Test your changes before submitting
   - Ensure no existing functionality is broken

2. **Test against multiple FTP clients**
   - Test with popular clients (FileZilla, WinSCP, CuteFTP, etc.)
   - Provide reproducible test results showing your changes work correctly
   - Include specific client names and versions tested

3. **Avoid adding dead code**
   - Do not add support for unused or ancient RFC commands without demonstrated real-world need
   - Every addition increases maintenance burden

4. **If you believe RFC compliance fixes a specific issue**
   - Provide a **working example** demonstrating the problem
   - Show which specific clients or scenarios are affected
   - Explain why the change is necessary (e.g., security issue, wrong behavior with common clients)
   - Demonstrate that your fix doesn't break compatibility with other clients

## Submitting Issues

When reporting bugs or requesting features:

1. **Provide reproducible steps**
   - Include specific FTP client name and version
   - Describe exact steps to reproduce the issue
   - Include relevant logs or error messages

2. **Explain the real-world impact**
   - Why does this matter for actual users?
   - Which clients or workflows are affected?

## What Will Be Rejected

Pull requests and issues will be closed without further notice if they:

- Contain code that does not compile
- Break existing functionality
- Add RFC compliance for unused commands without demonstrating real-world need
- Lack proper testing across multiple FTP clients
- Do not provide reproducible examples when claiming to fix specific issues

---

**Note:** We understand that RFC standards exist for good reasons, but this project explicitly prioritizes compatibility with existing FTP clients over theoretical compliance. If you believe strict RFC compliance is necessary for your use case, this may not be the right FTP server for your needs.
