# Alias FAQ

## What does Alias protocol enable fo end-users?

As end-users, Alias protocol enable you :
- to manage independantly their data and its third-party access, by getting back full control.
- to decide freely who can do manage their data for them, avoiding Identity Provider data lock-in.
- to share data from multiple platform in only one action by breaking identity providers silos.
(My photos from Google, Facebook, Twitter, FlickR can be shared in one click)
- to know exactly what of your data is requested form 3rd-parties and when, and then to trace history of your data
- to know who shared your data with other 3rd-parties
- to revoke access to your data anytime for any reason to any application.

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
Authorization server and resource server can be behing 2 different firewalls, making data authorization and management decentralized.

In the classic OAuth 2.0 flows, the authorization server and the resource server are behind the same firewall, 
giving full power and control about sharing capabilities to the Identity Provider (i.e. Facebook, Amazon, Google etc...). 
The Identity Provider decides what can be shared to whom via its API, and the user is limited into making data exportable 
to what the Identity provider allows in its API terms of service.

By enabling the resource server and the authorization server to be controled by 2 different entities ,Alias enable users to 
freely decide where their data is stored (on the server of their choice) and decide the Alias authorization server that
will manage its permissions. For instance with Alias, as a end-user, the access to my Facebook and Google data can be managed by a 
3rd-party Identity provider that will better represent ny user interest that these 2 Identity providers who used to managed it in Silos and 
with their own governance.


