/* global window */

import React, { Component } from 'react';
import { base64ToByteArray, byteArrayToBase64 } from 'lib/convert';

class Login extends Component {
  constructor(props) {
    super(props);

    this.handleStartAuth = this.handleStartAuth.bind(this);
  }
  initAuth() {
    const { publicKey, onCompleteLogin } = this.props;

    const parsed = {
      ...publicKey,
      challenge: base64ToByteArray(publicKey.challenge),
      allowCredentials: publicKey.allowCredentials.map(data => ({
        ...data,
        id: base64ToByteArray(data.id),
      })),
    };

    navigator.credentials.get({ publicKey: parsed })
      .then(response => {
        onCompleteLogin({
          credentials: btoa(JSON.stringify({
            id: response.id,
            type: response.type,
            rawId: byteArrayToBase64(response.rawId),
            response: {
              clientDataJSON: byteArrayToBase64(response.response.clientDataJSON),
              authenticatorData: byteArrayToBase64(response.response.authenticatorData),
              signature: byteArrayToBase64(response.response.signature),
              userHandle: response.response.userHandle
                ? byteArrayToBase64(response.response.userHandle)
                : null,
            },
          })),
        });
      })
      .catch(error => {
        console.log('nay', error, error.message);
      });
  }

  handleStartAuth(event) {
    event.preventDefault();
    this.initAuth();
  }

  /**
   * Render a description for this input
   *
   * @return {HTMLElement}
   */
  renderDescription() {
    const { ss: { i18n } } = window;

    return (
      <p>
        {i18n._t(
          'MFAWebAuthnLogin.DESCRIPTION',
          'Use your security key'
        )}
      </p>
    );
  }


  render() {
    const { moreOptionsControl } = this.props;

    return (
      <form className="mfa-login-web-authn__container">
        <div className="mfa-login-web-authn__content">
          {this.renderDescription()}
        </div>
        <button onClick={this.handleStartAuth}>Do it</button>
        {moreOptionsControl}
        <div className="mfa-login-web-authn__icon" />
      </form>
    );
  }
}

export default Login;