# Alias FAQ

## What does Alias protocol enable for end-users?

As end-users, Alias protocol enable you :
- to manage independantly their data and its third-party access, by getting back full control on data and permissions.
- to decide freely who can do manage their data for them, avoiding Identity Provider data lock-in.
- to share data from multiple platform in only one action, by breaking identity providers silos.
(My photos from Google, Facebook, Twitter, FlickR can be shared in one click)
- to know exactly what of your data is requested form 3rd-parties and when, and then to trace history of your data for later purposes
- to know who shared your data with other 3rd-parties of their network, and then 
- to revoke access to your data to any application at anytime for any reason.

It is not your employer who pays your for your work that should control how you manage and spend your money? It should be the same for data. It is not to companies who provides you platforms that your work for wuth your data that should control how do you manage your data.

## Why a new protocol?

Because current authorization protocols  and framework, espcially OAuth 2.0, have not been made and are not adapted for
a world where users own and control all their data.

Since new regulations about data portability (GDPR in Europe and CCPA in California), now every user is able to ask
a full export of its data to be stored anywhere, breaking Identity Provider (i,e Facebook, Google, Amazon, your Bank, you Telecom operator) etc monopoly and control. 
In that context, users can now own fully a copy of their data and share it to whom they want. They can now become theoretically independant
from previous Identity providers, by becoming their own Identity Provider if they are able to install a server to do so 
themselves, or theoretically choose the Identity provider that is the best delivering value for them about managing their 
personal data and permissions. Previous protocols (OpenID, OAuth1.0, OAuth1.a, OAuth 2.0, OpenID Connect, UMA) have been all invented 
in a world where the data would be managed by the entity that collected the data(i,e Facebook, Google, Amazon, your Bank, 
you Telecom operator). This situation is giving too much power to the Identity provider and deserve the user about his data.
We believe that users must be able to have more control by separating who stores the data, and who manage access to the data.

## What Alias brings to OAuth2.0?
With Alias, the Authorization server and the resource server can be behind 2 different firewalls, making data authorization  management and storage decentralized.

In the classic OAuth 2.0 flows, the authorization server and the resource server are behind the same firewall, 
giving full power and control about sharing capabilities to the Identity Provider (i.e. Facebook, Amazon, Google etc...). 
The Identity Provider decides what can be shared to whom via its API, and the user is limited into making data exportable 
to what the Identity provider allows in its API terms of service.

By enabling the resource server and the authorization server to be controled by 2 different entities ,Alias enable users to 
freely decide where their data is stored (on the server of their choice) and decide the Alias authorization server that
will manage its permissions. For instance with Alias, as a end-user, the access to my Facebook and Google data can be managed by a 3rd-party Identity provider that will better represent ny user interest that these 2 Identity providers who used to managed it in Silos and with their own governance.

## Why aren't you using a blockchain?

Because we can decentralize smarter and better, more efficiently, with more resilience and cheaper with protocol like DNS and Git that with a blockchain

Blockchain is a replicated database protocol, enabling honest nodes of the network to share and synchronize a ledger avoiding attacks from malhonest nodes. Each writing in the replicated ledger is based on mathematical problems solving using computing power competition over the network, called *proof of work*. Each writing is processed at the end of each transaction block when a node of the network has successfully solved the *proof of work* problem. A transaction is validated when enough blocks considered honest are validated. In the example of Bitcoin, it takes 6 blocks for a duration of 60 minutes.

Most of the Blockchain projects are not using it for main Blockchain features which are : 
- immutability of history to keep track of all transaction history
- avoiding double spending by trusting only the most rapidly mathematically solved chain of blocks (by the honest nodes)

but just surfing on the hype to get a crytpocurrency mining community and then try creating a utility token economy that is the only economic model. 

Compared to DNS and Git that we already have, main features of Blockchain are unnecessary in the digital identity world and others are even making it impossible to apply.

- Blockchains enable the unicity of a namespace (like Namecoin), that can be achieved by DNS
- Blockchain keeps the history of transactions, that we can achieve with git, rotative signture and merkle-tree mechanisms
- Blockchain are slow, as it takes few blocks (minutes to dozen of minutes) to validate a transaction. Where you can wait for 1 hour to transfer money like in Bitcoin, would you wait 30min to transfer your data and login to a platform?
- When blockchain are not slow, you need to pay a high fee to accelerate the validation from the network. Would you pay few dollars per login to a platform?
- When Blockchains transaction are cheaper and fast, they are centralized.  Then, you are not decentralized and you are not guarantee to have your data permissions decentralized


## What do you mean by a progressive Identity? 

We believe that we have different identity representations that are shallower or deeper according to our relationships to people or entities.

We can go progressively from : 
- Anonymous
- Pseudonymous
- Self-asserted
- Socially validated
- Officially Certified (by an authoririty, like a government ID, or a bank)

This is why we claim that everyone must be able to express the identity side they want to whom they want, at any time and to any. And that like in real life, it should go progressively from a minimum viable identity relationship , called in security 
