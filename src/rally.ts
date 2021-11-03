/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

import { browser, Tabs } from "webextension-polyfill-ts";

import { initializeApp } from "firebase/app"
import { connectAuthEmulator, getAuth, onAuthStateChanged, signInWithCustomToken } from "firebase/auth";
import { connectFirestoreEmulator, getFirestore, doc, onSnapshot, getDoc } from "firebase/firestore";

import { v4 as uuidv4 } from "uuid";

const CORE_ADDON_ID = "rally-core@mozilla.org";
const SIGNUP_URL = "https://rally.mozilla.org/rally-required";

export enum runStates {
  RUNNING,
  PAUSED,
  ENDED
}

export enum authProviders {
  GOOGLE = "google.com",
  EMAIL = "email",
}

export enum webMessages {
  WEB_CHECK = "rally-sdk.web-check",
  COMPLETE_SIGNUP = "rally-sdk.complete-signup",
  WEB_CHECK_RESPONSE = "rally-sdk.web-check-response",
  COMPLETE_SIGNUP_RESPONSE = "rally-sdk.complete-signup-response",
  CHANGE_STATE = "rally-sdk.change-state"
}

export class Rally {
  private _keyId: boolean;
  private _key: boolean;
  private _namespace: boolean;
  private _enableDevMode: boolean;
  private _rallyId: string;

  _state: runStates;
  _authStateChangedCallback: (user: any) => Promise<void>;
  _auth: any;
  _db: any;
  _rallySite: string;
  private _port: any;
  private _studyId: string;
  private _signedIn: any;
  private _enableFirebase: boolean;
  private _enableEmulatorMode: boolean;

  /**
   * Initialize the Rally library.
   *
   * @param {String} schemaNamespace
   *        The namespace for this study. Must match the server-side schema.s
   *
   * @param {Object} rallyConfig
   *        Configuration for Rally SDK.
   *
   * @param {boolean} rallyConfig.enableDevMode
   *        Whether or not to initialize Rally.js in developer mode.
   *        In this mode we do not attempt to connect to Firebase, and allow messages to enable/disable enrollment.
   *
   * @param {Object} rallyConfig.rallyCoreConfig
   *        Configuration for the Rally Core Add-on.
   *
   * @param {Object} rallyConfig.rallyWebPlatformConfig
   *        Configuration for the Rally Web Platform.
   *
   * @param {String} rallyConfig.rallyWebPlatformConfig.rallySite
   *        A string containing the Rally Web Platform site.
   *
   * @param {object} rallyConfig.rallyWebPlatformConfig.firebaseConfig
   *        An object containing the Firebase backend configuration.
   *
   * @param {object} rallyConfig.rallyWebPlatformConfig.enableEmulatorMode
   *        Whether or not to initialize Rally.js in emulator mode.
   *        In this mode the SDK attempts to use a local Firebase emulator. Note that the firebaseConfig must still be provided.
   *
   * @param {Function} rallyConfig.stateChangeCallback
   *        A function to call when the study is paused or running.
   *        Takes a single parameter, `message`, which is the {String}
   *        received regarding the current study state ("paused" or "running".)
   *
   * @param {String} rallyConfig.studyId
   *        A string containing the unique name of the study, separate from the Firefox add-on ID and Chrome extension ID.
   *
   */
  constructor({ enableDevMode, rallyCoreConfig, rallyWebPlatformConfig, stateChangeCallback, studyId }) {
    if (!(rallyCoreConfig || rallyWebPlatformConfig)) {
      throw new Error("Rally.initialize - Initialization failed, must specify at least one of: rally web platform or core add-on config");
    }

    if (!rallyCoreConfig) {
      console.warn("No Rally Core Add-on config specified");
    }

    if (!rallyWebPlatformConfig) {
      console.warn("No Rally Web Platform config specified");
    }

    const { enableEmulatorMode, firebaseConfig, rallySite } = rallyWebPlatformConfig;
    const { key, schemaNamespace } = rallyCoreConfig;

    if (!stateChangeCallback) {
      throw new Error("Rally.initialize - Initialization failed, stateChangeCallback is required.")
    }

    if (typeof stateChangeCallback !== "function") {
      throw new Error("Rally.initialize - Initialization failed, stateChangeCallback is not a function.")
    }

    this._namespace = Boolean(schemaNamespace);
    this._keyId = key.kid;
    this._key = Boolean(key);
    this._enableDevMode = Boolean(enableDevMode);
    this._enableFirebase = Boolean(rallyWebPlatformConfig);
    this._enableEmulatorMode = Boolean(enableEmulatorMode);
    this._rallySite = rallySite;
    this._studyId = studyId;

    this._signedIn = false;

    // Set the initial state to paused, and register callback for future changes.
    this._state = runStates.PAUSED;
    this._stateChangeCallback = stateChangeCallback;

    if (this._enableDevMode) {
      console.warn("Rally SDK - running in developer mode, not using Firebase");

      // Listen for incoming messages from the Rally Web Platform site.
      browser.runtime.onMessage.addListener((m, s) => this._handleWebMessage(m, s));

      return;
    }

    if (!this._enableFirebase) {
      console.info("Rally SDK - Firebase disabled, using Rally Core Add-on");

      this._checkRallyCore().then(() => {
        console.debug("Rally.initialize - Found the Core Add-on.");

        // Listen for incoming messages from the Core Add-on.
        browser.runtime.onMessageExternal.addListener(
          (m, s) => this._handleExternalMessage(m, s));

        return;
      }).catch(async () => {
        // The Core Add-on was not found and we're not in developer
        // mode. Trigger the sign-up flow.
        if (!this._enableDevMode) {
          await browser.tabs.create({ url: SIGNUP_URL });
        }

        return;
      });
    }

    console.debug("Rally SDK - using Firebase config:", firebaseConfig);
    const firebaseApp = initializeApp(firebaseConfig);

    this._auth = getAuth(firebaseApp);
    this._db = getFirestore(firebaseApp);

    if (this._enableEmulatorMode) {
      console.debug("Rally SDK - running in Firebase emulator mode:", firebaseConfig);

      connectAuthEmulator(this._auth, 'http://localhost:9099');
      connectFirestoreEmulator(this._db, 'localhost', 8080);
    }

    this._authStateChangedCallback = async (user: any) => {
      if (user) {
        // Record that we have signed in, so we don't keep trying to onboard.
        this._signedIn = true;

        // This is a restricted user, which can see a minimal part of the users data.
        // The users Firebase UID is needed for this, and it is available in a custom claim on the JWT.
        const idTokenResult = await this._auth.currentUser.getIdTokenResult();
        const uid = idTokenResult.claims.firebaseUid;

        // This contains the Rally ID, need to call the Rally state change callback with it.
        onSnapshot(doc(this._db, "extensionUsers", uid), extensionUserDoc => {
          if (!extensionUserDoc.exists()) {
            throw new Error("Rally onSnapshot - extensionUser document does not exist");
          }

          // https://datatracker.ietf.org/doc/html/rfc4122#section-4.1.7
          const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

          const data = extensionUserDoc.data();

          if (data && data.rallyId) {
            if (data.rallyId.match(uuidRegex)) {
              // Stored Rally ID looks fine, cache it and call the Rally state change callback with it.
              this._rallyId = data.rallyId;
            } else {
              // Do not loop or destroy data if the stored Rally ID is invalid, bail out instead.
              throw new Error(`Stored Rally ID is not a valid UUID: ${data.rallyId}`);
            }
          }
        });

        onSnapshot(doc(this._db, "studies", this._studyId), async studiesDoc => {
          // TODO do runtime validation of this document
          if (!studiesDoc.exists()) {
            throw new Error("Rally onSnapshot - studies document does not exist");
          }
          const data = studiesDoc.data();
          if (data.studyPaused && data.studyPaused === true) {
            if (this._state !== runStates.PAUSED) {
              this._pause();
            }
          } else {
            const userStudiesDoc = await getDoc(doc(this._db, "users", uid, "studies", this._studyId));
            // TODO do runtime validation of this document
            if (userStudiesDoc && !userStudiesDoc.exists()) {
              // This document is created by the site and may not exist yet.
              console.warn("Rally.onSnapshot - userStudies document does not exist yet");
              return;
            }

            const data = userStudiesDoc.data();

            if (data.enrolled && this._state !== runStates.RUNNING) {
              this._resume();
            }
          }

          if (data.studyEnded === true) {
            if (this._state !== runStates.ENDED) {
              this._end();
            }
          }
        });

        onSnapshot(doc(this._db, "users", uid, "studies", this._studyId), async userStudiesDoc => {
          if (!userStudiesDoc.exists()) {
            // This document is created by the site and may not exist yet.
            console.warn("Rally.onSnapshot - userStudies document does not exist");
            return;
          }

          const data = userStudiesDoc.data();
          if (data.enrolled) {
            this._resume();
          } else {
            this._pause();
          }
        });
      } else {
        await this._promptSignUp();
      }

      browser.runtime.onMessage.addListener((m, s) => this._handleWebMessage(m, s));
    }

    onAuthStateChanged(this._auth, this._authStateChangedCallback);
  }

  /**
   * Prompt users to sign-in to the Rally Web Platform.
   *
   * Called when no auth token is present, or is not valid.
   */
  async _promptSignUp() {
    let loadedTab: Tabs.Tab;

    const tabs = await browser.tabs.query({ url: `${this._rallySite}/*` });
    // If there are any tabs with the Rally site loaded, focus the latest one.
    if (tabs && tabs.length > 0) {
      loadedTab = tabs.pop();
      await browser.windows.update(loadedTab.windowId, { focused: true });
      await browser.tabs.update(loadedTab.id, { highlighted: true, active: true });
    } else {
      // Otherwise, open the website.
      loadedTab = await browser.tabs.create({
        url: this._rallySite
      });
    }
  }

  /**
   * Check if the Core addon is installed.
   *
   * @returns {Promise} resolved if the core addon was found and
   *          communication was successful, rejected otherwise.
   */
  async _checkRallyCore() {
    try {
      const msg = {
        type: "core-check",
        data: {}
      }
      let response =
        await browser.runtime.sendMessage(CORE_ADDON_ID, msg, {});

      if (response
        && response.type == "core-check-response") {
        if (response.data
          && "enrolled" in response.data
          && response.data.enrolled === true
          && "rallyId" in response.data
          && response.data.rallyId !== null) {
          this._rallyId = response.data.rallyId;
        } else {
          throw new Error(`Rally._checkRallyCore - core addon present, but not enrolled in Rally`);
        }
      } else {
        throw new Error(`Rally._checkRallyCore - unexpected response returned ${response}`);
      }

    } catch (ex) {
      throw new Error(`Rally._checkRallyCore - core addon check failed with: ${ex}`);
    }
  }

  /**
   * Pause the current study.
   */
  _pause() {
    if (this._state !== runStates.PAUSED) {
      this._state = runStates.PAUSED;
      this._stateChangeCallback(runStates.PAUSED);
    }
  }

  /**
   * Resume the current study, if paused.
   */
  _resume() {
    if (this._state !== runStates.RUNNING) {
      this._state = runStates.RUNNING;
      this._stateChangeCallback(runStates.RUNNING);
    }
  }

  /**
   * End the current study. This leaves the study installed,
   * but marks it as finished. May be resumed later (in case of error).
   *
   * @param runState
   * @param rallyId
   */
  _end() {
    this._state = runStates.ENDED;
    this._stateChangeCallback(runStates.ENDED);
  }

  /**
   * Called when the state changes, this must be overridden by the study.
   *
   * @param runState
   */
  private _stateChangeCallback(runState: runStates) {
    throw new Error("Method not implemented, must be provided by study.");
  }

  /**
  * Handles messages coming in from the external website.
  *
  * @param {Object} message
  *        The payload of the message. May be an empty object, or contain auth credential.
  *
  *        email credential: { email, password, providerId }
  *        oAuth credential: { oauthIdToken, providerId }
  *
  * @param {runtime.MessageSender} sender
  *        An object containing information about who sent
  *        the message.
  * @returns {Promise} The response to the received message.
  *          It can be resolved with a value that is sent to the
  *          `sender` or rejected in case of errors.
  */
  async _handleWebMessage(message: { type: webMessages, data }, sender: any) {
    if (sender.id !== browser.runtime.id) {
      throw new Error(`Rally._handleWebMessage - unknown sender ${sender.id}, expected ${browser.runtime.id}`);
    }
    console.log("Rally._handleWebMessage - received web message", message, "from", sender);
    // ** IMPORTANT **
    //
    // The website should *NOT EVER* be trusted. Other addons could be
    // injecting content scripts there too, impersonating the website
    // and performing requests on its behalf.
    //
    // Do not ever add other features or messages here without thinking
    // thoroughly of the implications: can the message be used to leak
    // information out? Can it be used to mess with studies?

    switch (message.type) {
      case webMessages.WEB_CHECK:
        // The `web-check` message should be safe: any installed extension with
        // the `management` privileges could check for the presence of the
        // Rally SDK and expose that to the web. By exposing this ourselves
        // through content scripts enabled on our domain, we don't make things
        // worse.
        // FIXME check internally to see if we need this yet or not.
        // Now that the site is open, send a message asking for a JWT.
        if (!this._signedIn) {
          console.debug("not signed in, sending complete_signup request");
          await browser.tabs.sendMessage(sender.tab.id, { type: webMessages.COMPLETE_SIGNUP, data: { studyId: this._studyId } });
        } else {
          console.debug("already signed in, not sending complete_signup request");
        }

        console.debug("sending web-check-response to sender:", sender, " done");
        await browser.tabs.sendMessage(sender.tab.id, { type: webMessages.WEB_CHECK_RESPONSE, data: {} });
        break;

      case webMessages.COMPLETE_SIGNUP_RESPONSE:
        // The `complete-signup-response` message should be safe: It's a response
        // from the page, containing the credentials from the currently-authenticated user.
        //
        // Note that credentials should *NEVER* be passed to web content, but accepting them from web content
        // should be relatively safe. An attacker-controlled site (whether through MITM, rogue extension, XSS, etc.)
        // could potentially pass us a working credential that is attacker-controlled, but this should not cause the
        // extension to send data anywhere attacker-controlled, since the data collection endpoint is hardcoded and signed
        // along with the extension.
        await this._completeSignUp(message.data);

        break;
      case webMessages.CHANGE_STATE:
        console.debug("Rally SDK - received rally-sdk.change-state in dev mode");

        if (!this._enableDevMode) {
          throw new Error("Rally SDK state can only be changed directly when in developer mode.");
        }

        if (!message.data.state) {
          console.debug(`Rally SDK - No state change requested: ${message.data}`);
          return;
        }

        switch (message.data.state) {
          case "resume":
            console.debug("Rally SDK - dev mode, resuming study");
            if (!this._rallyId) {
              this._rallyId = uuidv4();
              console.debug(`Rally SDK - dev mode, generated Rally ID: ${this._rallyId}`);
            }

            this._resume();

            break;
          case "pause":
            console.debug("Rally SDK - dev mode, pausing study");
            this._pause();

            break;
          case "end":
            console.debug("Rally SDK - dev mode, ending study");
            this._end();

            break;
          default:
            console.debug(`Rally SDK - invalid state change requested: ${message.data.state}`);
        }

        break;
      default:
        console.warn(`Rally._handleWebMessage - unexpected message type "${message.type}"`);
    }
  }

  /**
   * Handles messages coming in from external addons.
   *
   * @param {Object} message
   *        The payload of the message.
   * @param {runtime.MessageSender} sender
   *        An object containing informations about who sent
   *        the message.
   * @returns {Promise} The response to the received message.
   *          It can be resolved with a value that is sent to the
   *          `sender`.
   */
  _handleExternalMessage(message, sender) {
    // We only expect messages coming from the core addon.
    if (sender.id != CORE_ADDON_ID) {
      return Promise.reject(
        new Error(`Rally._handleExternalMessage - unexpected sender ${sender.id}`));
    }

    switch (message.type) {
      case "pause":
        this._pause();
        break;
      case "resume":
        this._resume();
        break;
      case "uninstall":
        return browser.management.uninstallSelf({ showConfirmDialog: false });
      default:
        return Promise.reject(
          new Error(`Rally._handleExternalMessage - unexpected message type ${message.type}`));
    }
  }

  /**
   * Complete Rally sign-up process. This will be called after sign up has completed and the auth
   * token is available for logging into the Web Platform.
   *
   * @param data - fetch result containing the auth token (JWT) to log in to the Rally Web Platform.
   * @returns {boolean} - true if authentication succeeds.
   */

  async _completeSignUp(data) {
    console.debug("Rally._completeSignUp called:", data);
    try {
      if (!data || !data.rallyToken) {
        throw new Error(`Rally._completeSignUp - rally token not well-formed: ${data.rallyToken}`);
      }

      console.debug("Rally._completeSignUp - ", data);
      // Pause study when new credentials are passed.
      if (this._auth.currentUser) {
        this._pause();
      }

      await signInWithCustomToken(this._auth, data.rallyToken);
      return true;
    } catch (ex) {
      console.error("Rally._completeSignUp - signInWithCustomToken failed:", ex.code, ex.message);
      return false;
    }
  }

  /**
   * Returns the Rally ID, if set.
   *
   * @returns string - the Rally ID, when available.
   */
  get rallyId() {
    return this._rallyId;
  }

  /**
   * Validate the provided encryption keys.
   *
   * @param {Object} key
   *        The JSON Web Key (JWK) used to encrypt the outgoing data.
   *        See the RFC 7517 https://tools.ietf.org/html/rfc7517
   *        for additional information. For example:
   *
   *        {
   *          "kty":"EC",
   *          "crv":"P-256",
   *          "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
   *          "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
   *          "kid":"Public key used in JWS spec Appendix A.3 example"
   *        }
   *
   * @throws {Error} if either the key id or the JWK key object are
   *         invalid.
   */
  _validateEncryptionKey(key) {
    if (typeof key !== "object") {
      throw new Error(`Rally._validateEncryptionKey - Invalid encryption key: ${key}`);
    }

    if (!("kid" in key && typeof key.kid === "string")) {
      throw new Error(`Rally._validateEncryptionKey - Missing or invalid encryption key ID in key: ${key}`);
    }
  }

  /**
   * Submit an encrypted ping through the Rally Core addon.
   *
   * @param {String} payloadType
   *        The type of the encrypted payload. This will define the
   *        `schemaName` of the ping.
   * @param {Object} payload
   *        A JSON-serializable payload to be sent with the ping.
   */
  async sendPing(payloadType, payload) {
    // When in developer mode, dump the payload to the console.
    if (this._enableDevMode) {
      console.log(
        `Rally.sendPing - Developer mode. ${payloadType} will not be submitted`,
        payload
      );
      return;
    }

    // When paused, do not send data.
    if (this._state === runStates.PAUSED) {
      console.debug("Rally.sendPing - Study is currently paused, not sending data");
      return;
    }

    // Wrap everything in a try block, as we don't really want
    // data collection to be the culprit of a bug hindering user
    // experience.
    try {
      this._validateEncryptionKey(this._key);

      const msg = {
        type: "telemetry-ping",
        data: {
          payloadType: payloadType,
          payload: payload,
          namespace: this._namespace,
          keyId: this._keyId,
          key: this._key
        }
      }
      await browser.runtime.sendMessage(CORE_ADDON_ID, msg, {});
    } catch (ex) {
      console.error(`Rally.sendPing - error while sending ${payloadType}`, ex);
    }
  }
}
