# cw-auth: cosmwasm off-chain auth

a utility that takes an ADR-036 signed document containing an auth token, decodes
and verifies it, returning the inner token if it is valid

[cw-auth-js](https://github.com/aswever/cw-auth-js) is a complementary javascript 
library with functions allowing users to sign tokens with Keplr and agents validate
the tokens and send them in the correct format.

## how to use

the `authorize` function takes a message with a signed and encoded auth token, validates
the authorization (including that the correct user has signed the token, specifying the
address of the message sender as their agent), and returns the message along with its 
unwrapped auth token.

```rust
pub fn authorize<M, A: DeserializeOwned>(
    message: MsgWithAuth<M>, 
    info: &MessageInfo, 
    env: &Env
) -> Result<Authorized<A, M>, AuthError>
```

you can use this in your contract's `execute` function to validate and parse the authorized
message:

```rust
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Post(msg) => post(deps, authorize(msg, &info, &env)?),
        ...
    }
}
```

which will then be available to you as an `AuthMsg` to use as you wish.

```rust
pub fn post(mut deps: DepsMut, msg: AuthMsg<PostMsg>) -> Result<Response, ContractError> {
    let user_addr = msg.auth_token.user;
    let username = msg.auth_token.meta.username;
    let content = msg.message.content;
    ...
```

### the auth token

```rust
pub struct AuthToken<T> {
    pub user: Addr,
    pub agent: Addr,
    pub expires: u64,
    pub meta: T,
}
```

the auth token includes the addresses of the user and the agent (who may be allowed to 
take actions on behalf of the user) as well as an expiration timestamp (in seconds) and
a meta object containing whatever other properties you'd like to embed.

### the Authorization object

the `Authorization` object has a `document`, a base-64 encoded serialized 
[ADR-036](https://docs.cosmos.network/master/architecture/adr-036-arbitrary-signature.html) 
sign doc with an auth token (as JSON) as its data, along with the (Secp256k1) signature and
pubkey of the signer.

```rust
pub struct Authorization {
    pub document: String,
    pub signature: String,
    pub pubkey: String,
}
```

this can then be combined with any message to create a `MsgWithAuth`.

```rust
pub struct MsgWithAuth<T> {
    pub authorization: Authorization,
    pub message: T,
}
```
