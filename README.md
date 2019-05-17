# Alias protocol reference design. 
Backend is mainly in Python & Go.

### Summary

Alias is a protocol based on OAuth 2.0 enabling decentralized data export authorizations. When implmented, Alias enables for users to decide to share the data they want, to whom they want, without limitations from any Identity Provider and in fine grained control.

Here's a [technical summary of the core concepts of Alias](https://github.com/progressive-identity/sandbox/blob/master/doc/SUMMARY)

### What it brings more than OAuth 2.0?
In classic OAuth 2.0, the authorization server and the resource server are behing the same firewall, giving full power and control about sharing capabilities to the Identity Provider (i.e. Facebook, Amazon, Google etc...). The Identity Provider decides what can be shared to whom via its API, and the user is limited into making data exportable.

Because of new regulations about data portability (GDPR in Europe and CCPA in California), now every user is able to ask a full export of its data to be stored anywhere, breaking Identity Provider monopoly and control. In that context, users can now own fully a copy of their data and share it to who they want. They can now become  theoretically independant from previous Identity provider, by becoming their own Identity Provider if they are able to install or choose the Identity provider that is the best delivering value for them/

Because a large majority of users will still want to delegate authorizations to a trusted 3rd-party to manage permissions (as we do for banks for our money, or to wallet managers for out Bitcoins), Alias enables users to delegate authorization to any Authorization server that will implement Alias protocol. In the Alias protocol ecosystem users decide where their data is stored (on the server of their choice) and decide the Alias authorization server that will manage its permissions.

### An Opinion about Identity

To understand the decentralized identity challenge Alias is tackling, please read our [Manifesto for a Progressive Identity](https://github.com/progressive-identity/ref/wiki/Manifesto-for-a-Progressive-Identity).

### Expected Roadmap

Here's a [summary of the implementation next steps for ALIAS to achieve personal data authorization decentralization](https://github.com/progressive-identity/ref/wiki/Roadmap-of-ALIAS-protocol-delivery)
