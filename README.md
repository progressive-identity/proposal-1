# Alias protocol reference design.

Features:

- Reference design for a Alias Authorization & Resource server (built in Python);
- Sample code for a Alias client (built in Python);
- Builds, signs and verifies tokens&orders (algo: Ed25519 or Secp256k1, SHA-256);
- Key rotation management;
- Revocation management and propagation;
- Order storage based on a relation SQL database (sqlite by default);
- TLS client-side certificate verification (TLS reverse-proxy built in Go);

Here's a [technical summary of the core concepts of
Alias](https://github.com/progressive-identity/sandbox/blob/master/doc/SUMMARY).

### Summary of Alias protocol

Alias is a protocol enabling decentralized data export authorizations. When implemented, Alias enables for users to decide to share the data they want, to whom they want, without limitations from any centralized Identity Provider, and in fine grained control.

Technically, Alias is a decentralized protocol based on OAuth 2.0, where each user, identified by an cryptographic alias, can let third-parties ("clients") access to their data stored in  servers ("resource servers"). Access to the data is controlled by an Authorization server ("authorization servers") that manages permissions and scopes.
The main innovation of Alias is that the resource server and the authorization server do not need to be behind the same firewall, enabling users to decide freely and in full control who store their data and who manage permissions in a decentralized way.

### Alias : Adding decentralization of data portability to OAuth2.0

In the classic OAuth 2.0 flows, the authorization server and the resource server are behind the same firewall, giving full power and control about sharing capabilities to the Identity Provider (i.e. Facebook, Amazon, Google etc...). The Identity Provider decides what can be shared to whom via its API, and the user is limited into making data exportable to what the Identity provider allows.

Because of new regulations about data portability (GDPR in Europe and CCPA in California), now every user is able to ask a full export of its data to be stored anywhere, breaking Identity Provider monopoly and control. In that context, users can now own fully a copy of their data and share it to who they want. They can now become *theoretically* independent from previous Identity providers, by becoming their own Identity Provider if they are able to install a server to do so themselves, or *theoretically* choose the Identity provider that is the best delivering value for them about managing their personal data and permissions.

As we seen in Bitcoin, a large majority of users will still want to delegate authorizations to a trusted 3rd-party to manage permissions, as they do until today with banks for their money, or to wallet managers for their Bitcoins/Crytocurrencies. In the Alias protocol ecosystem,users decide where their data is stored (on the server of their choice) and decide the Alias authorization server that will manage its permissions.

### Alias manifesto for a *Progressive Identity*

To understand the decentralized identity challenge Alias is tackling, please read our [Manifesto for a Progressive Identity](https://github.com/progressive-identity/ref/wiki/Manifesto-for-a-Progressive-Identity).

### Expected Alias Roadmap

Here's a [summary of the implementation next steps for ALIAS to achieve personal data authorization decentralization](https://github.com/progressive-identity/ref/wiki/Roadmap-of-ALIAS-protocol-delivery)
