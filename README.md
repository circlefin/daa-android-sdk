# daa-android-sdk

Android SDK for Circle Digital Asset Accounts. It lets your end users approve
sensitive operations, and register the passkey they approve with, through
Circle's hosted passkey ceremony (Strong Customer Authentication, or SCA). It
also contains the device-key primitives for attested authentication.

The SDK holds no credentials and makes no calls to Circle's APIs. Your backend
does that with the
[Circle Node SDK](https://github.com/circlefin/daa-node-sdk), and passes your
app only the short-lived token for one ceremony.

- [Requirements](#requirements)
- [Install](#install)
- [Passkey SCA (strong customer authentication)](#passkey-sca-strong-customer-authentication)
- [Owner AuthKey](#owner-authkey)
- [Development](#development)
- [Support and security reporting](#support-and-security-reporting)
- [License](#license)

## Requirements

- **minSdk 23.** Browser passkeys need Android 9 or later with a screen lock.
- **compileSdk 36 and Android Gradle Plugin 8.9.1 or later.** The SDK depends
  on `androidx.browser` 1.9.0, which requires both of every app that uses it.
  This raises only the SDK your app *compiles* against. It does not change
  your `minSdk` or `targetSdk`, or which devices can install your app.

  An app that still compiles against 35 fails the build in
  `checkDebugAarMetadata` (or `checkReleaseAarMetadata`) with:

  ```
  Dependency 'androidx.browser:browser:1.9.0' requires libraries and applications that
  depend on it to compile against version 36 or later of the
  Android APIs.
  ```

  Fix it by setting `compileSdk = 36` in your app module and, if needed,
  upgrading the Android Gradle Plugin to 8.9.1 or later.

## Install

The library is published to GitHub Packages, which requires authentication
even for public packages. Create a GitHub personal access token (classic) with
the `read:packages` scope, and put your GitHub username and the token in
`~/.gradle/gradle.properties` (not in your project, so the token is never
committed):

```properties
gpr.user=<your GitHub username>
gpr.key=<your token>
```

Then add the repository:

```kotlin
// settings.gradle.kts
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
        maven("https://maven.pkg.github.com/circlefin/daa-android-sdk") {
            credentials {
                username = providers.gradleProperty("gpr.user").orNull
                password = providers.gradleProperty("gpr.key").orNull
            }
        }
    }
}
```

Then add the dependency:

```kotlin
// app/build.gradle.kts
dependencies {
    implementation("com.circle.daa:daa-android-sdk:0.5.0")
}
```

To build against a local checkout instead, use Gradle's `includeBuild`, or
publish to a local directory with
`./gradlew publishAllPublicationsToStagingRepository` and point a `maven {}`
block at `build/staging-repo`.

## Passkey SCA (strong customer authentication)

When an operation needs the user's approval, such as a transfer, Circle asks
for a passkey ceremony. The SDK opens Circle's hosted ceremony page in a
browser tab over your app. The page shows the user what they are approving,
runs the passkey prompt, and returns the result to your app. Your app never
sees or draws the details the user approves, and never handles the passkey.

The page runs in an **Auth Tab** when the browser supports one (Chrome 137 and
later), which returns the result to the SDK directly. Otherwise it runs in a
**Custom Tab**, and the result returns through a callback activity that you
declare. It only runs in a [supported browser](#supported-browsers), never in a
`WebView`.

- [How it fits together](#how-it-fits-together)
- [Prerequisites](#prerequisites)
- [Declare the callback activity](#declare-the-callback-activity)
- [Publish `assetlinks.json`](#publish-assetlinksjson)
- [Quick start](#quick-start)
- [Checking your setup](#checking-your-setup)
- [Error handling](#error-handling)
- [Supported browsers](#supported-browsers)
- [Known behavior](#known-behavior)
- [Security checklist](#security-checklist)

### How it fits together

Approving an operation (step-up):

1. **Your app** asks your backend to start, with your own reference for the
   operation, for example `startTransfer(transferId)`.
2. **Your backend** opens a challenge for the exact request it intends to send,
   with your app's `redirectUri`. Circle returns a `challengeId` and a
   `frameToken`. Your backend stores the `challengeId` against that transfer
   and returns **only the `frameToken`** to your app.
3. **Your app** launches `DaaScaApproveContract` with the `frameToken`. The
   user approves in the browser tab, and the SDK returns
   `DaaScaResult.Completed`.
4. Your app sends `Completed.response` to your backend **unmodified**, with
   its own reference: `confirmTransfer(transferId, response)`.
5. **Your backend** sends the original request again, unchanged, with two
   headers: `X-Sca-Challenge-Id` (the `challengeId` it stored) and
   `X-Sca-Assertion` (`Completed.response`, as is).

The app never needs the `challengeId`.

Registering a passkey (enrollment) is the same round trip:

1. Your app asks your backend to start. Your backend opens a registration with
   your app's `redirectUri`, keeps the `registrationId` (for example in the
   user's session), and returns only the `frameToken`.
2. Your app launches `DaaScaEnrollContract` with the `frameToken` and sends
   `Completed.response` back unmodified.
3. Your backend parses that JSON text once and passes the object as
   `attestationResponse`, with its stored `registrationId`, to complete the
   registration.

Whether a user has a passkey yet is something your backend knows before any
ceremony: list the user's passkeys, and send a user with none through
enrollment instead of opening a challenge.

### Prerequisites

- **Circle registers your redirect URIs.** Give Circle the exact redirect URI
  your app uses in each environment, for example
  `https://app.example.com/sca/callback`. Circle matches it as an exact string.
- **Your backend passes the same `redirectUri`** whenever it opens a
  registration or a challenge with the
  [Circle Node SDK](https://github.com/circlefin/daa-node-sdk). That is what
  makes Circle return the result to your app. A URI Circle has not registered
  for you fails that backend call with error `420068`, and no `frameToken` is
  issued. Without a `redirectUri`, Circle opens a web ceremony that never
  returns to your app.
- **Approving an operation requires an `https` redirect URI** that is a
  verified App Link. A custom scheme (such as `com.example.app:/sca`) is
  accepted for enrollment only, because any app can register a custom scheme.
  `DaaScaApproveContract` throws `IllegalArgumentException` when it is
  constructed with a custom-scheme URI.
- **Enrollment with a custom scheme needs an Auth Tab.** In an Auth Tab the
  browser returns the redirect to your app alone. In a Custom Tab, Android
  would hand a custom-scheme redirect to any app that declares the scheme, so
  where no supported browser offers an Auth Tab the enrollment fails
  `Unsupported` with `InsecureRedirect` before anything opens. An `https`
  redirect URI still falls back to a Custom Tab, and is kept from other apps
  only while Android has verified your App Link (see
  [Publish `assetlinks.json`](#publish-assetlinksjson)). Use `https` for both
  ceremonies.
- The redirect URI must have no fragment, credentials, whitespace or
  non-ASCII characters, a lowercase scheme, and at most 2048 characters. An
  `https` host must be a lowercase domain name, not an IP address. An `https` URI must not
  include a port (not even `:443`): App Link verification reads
  `assetlinks.json` from the default port. The URI must also reach the app
  exactly as written, so it must not contain a `.` or `..` path segment
  (literal or `%2e`), and an `https` query must not contain `'`; browsers
  rewrite both. `DaaScaConfig` checks this when you construct it.

### Declare the callback activity

The SDK cannot declare this activity for you, because only your app knows its
redirect URI. Add it to your app's `AndroidManifest.xml`, with an intent filter
that matches your redirect URI exactly:

```xml
<activity
    android:name="com.circle.daa.sdk.sca.DaaScaCallbackActivity"
    android:exported="true"
    android:excludeFromRecents="true"
    android:taskAffinity=""
    android:theme="@android:style/Theme.Translucent.NoTitleBar">
    <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data
            android:scheme="https"
            android:host="app.example.com"
            android:path="/sca/callback" />
    </intent-filter>
</activity>
```

Each attribute matters:

- `exported="true"`: the browser starts it. The activity checks every intent it
  receives and drops anything that is not the result of the ceremony in
  progress, so another app cannot complete or end a ceremony through it.
- `taskAffinity=""`: the browser sometimes runs in its own task, for example on
  its first run, or after the user moves the tab into the browser app. An empty
  affinity starts the callback activity in a task of its own, so a callback it
  drops cannot bring your app to the front and end the ceremony the user is in.
- `excludeFromRecents="true"` and the translucent theme: the activity finishes
  immediately and shows nothing, so it should not appear on screen or in the
  recent apps list.
- `autoVerify="true"`: Android verifies that your app owns the domain, using
  the `assetlinks.json` file below. Without verification, an `https` redirect
  can open in the browser instead of your app, and an Auth Tab refuses it.

### Publish `assetlinks.json`

Serve this file at `https://<your redirect URI's host>/.well-known/assetlinks.json`,
for example `https://app.example.com/.well-known/assetlinks.json`, over HTTPS
with no redirects and with `Content-Type: application/json`:

```json
[
  {
    "relation": ["delegate_permission/common.handle_all_urls"],
    "target": {
      "namespace": "android_app",
      "package_name": "com.example.app",
      "sha256_cert_fingerprints": [
        "<SHA-256 of your release signing certificate>",
        "<SHA-256 of your debug signing certificate>"
      ]
    }
  }
]
```

List every certificate your app is signed with where it runs: the release
key (with Play App Signing, the app signing key shown in Play Console, not
your upload key) and the debug key you test with. `./gradlew signingReport`
prints the fingerprints of your local keys. Verification runs when the app is
installed, so reinstall after you change the file.

### Quick start

Construct the contracts once, as properties, and register them with
`registerForActivityResult`. Android can stop your app's process while the
browser is open. The activity-result registry then delivers the result to the
recreated activity, so keep your own reference for what the result belongs
to, such as the `transferId`, in saved state too. Your backend keeps the
`challengeId` and `registrationId`; the app never holds them.

```kotlin
import android.os.Bundle
import androidx.activity.ComponentActivity
import com.circle.daa.sdk.DaaEnvironment
import com.circle.daa.sdk.sca.DaaScaApproveContract
import com.circle.daa.sdk.sca.DaaScaConfig
import com.circle.daa.sdk.sca.DaaScaEnrollContract
import com.circle.daa.sdk.sca.DaaScaError
import com.circle.daa.sdk.sca.DaaScaResult

/** Your own backend's API. Your backend holds the Circle API key; your app never does. */
interface WalletBackend {
    /** Opens a challenge with your redirectUri, stores its challengeId, and returns the frameToken. */
    fun startTransfer(transferId: String, onStarted: (frameToken: String) -> Unit)

    /** Sends the transfer again with X-Sca-Challenge-Id (stored) and X-Sca-Assertion (assertion). */
    fun confirmTransfer(transferId: String, assertion: String)

    /** Opens a registration with your redirectUri, keeps its registrationId, and returns the frameToken. */
    fun startPasskeyRegistration(onStarted: (frameToken: String) -> Unit)

    /** Completes the registration it kept, with the response as attestationResponse. */
    fun completePasskeyRegistration(registrationResponse: String)
}

class TransferActivity : ComponentActivity() {
    lateinit var backend: WalletBackend // from your dependency injection

    private val sca = DaaScaConfig(DaaEnvironment.Sandbox, "https://app.example.com/sca/callback")

    // What the result belongs to. Saved below, because the result can arrive in a new process.
    private var transferId: String? = null
    private var registering = false

    private val approve =
        registerForActivityResult(DaaScaApproveContract(sca)) { result ->
            val transfer = transferId
            transferId = null
            setSendEnabled(true)
            if (transfer == null) return@registerForActivityResult
            when (result) {
                // Send the response exactly as returned. Do not parse or re-encode it.
                is DaaScaResult.Completed -> backend.confirmTransfer(transfer, result.response)
                DaaScaResult.Cancelled -> showMessage("Transfer not approved. You can try again.")
                is DaaScaResult.Failed -> showScaFailure(result)
            }
        }

    private val enroll =
        registerForActivityResult(DaaScaEnrollContract(sca)) { result ->
            if (!registering) return@registerForActivityResult
            registering = false
            when (result) {
                is DaaScaResult.Completed -> backend.completePasskeyRegistration(result.response)
                DaaScaResult.Cancelled -> showMessage("Passkey not created. You can try again.")
                is DaaScaResult.Failed ->
                    if (result.error == DaaScaError.AlreadyEnrolled) {
                        showMessage("You already have a passkey.")
                    } else {
                        showScaFailure(result)
                    }
            }
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        transferId = savedInstanceState?.getString(KEY_TRANSFER)
        registering = savedInstanceState?.getBoolean(KEY_REGISTERING) ?: false
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString(KEY_TRANSFER, transferId)
        outState.putBoolean(KEY_REGISTERING, registering)
    }

    fun onSendClicked(transfer: String) {
        // One ceremony at a time: keep the button disabled until the result arrives.
        setSendEnabled(false)
        backend.startTransfer(transfer) { frameToken ->
            // On the main thread, while this activity is started.
            transferId = transfer
            approve.launch(frameToken)
        }
    }

    fun onCreatePasskeyClicked() {
        backend.startPasskeyRegistration { frameToken ->
            registering = true
            enroll.launch(frameToken)
        }
    }

    private fun setSendEnabled(enabled: Boolean) {
        // Enable or disable your send button.
    }

    private fun showMessage(text: String) {
        // Show text to the user.
    }

    private fun showScaFailure(failure: DaaScaResult.Failed) {
        // See "Error handling".
    }

    private companion object {
        const val KEY_TRANSFER = "transferId"
        const val KEY_REGISTERING = "registering"
    }
}
```

`DaaScaConfig` takes:

| Parameter | Default | Description |
| --- | --- | --- |
| `environment` | | `DaaEnvironment.Sandbox` or `DaaEnvironment.Production`. Selects Circle's ceremony page. Use the environment your backend uses. |
| `redirectUri` | | Your callback URI, identical to the one Circle registered and your backend sends. |
| `circleOrigin` | Per environment | Leave unset unless Circle gives you a ceremony host for testing. Only `https` hosts on `circle.com` are accepted, and never with `Production`. |
| `approveTimeoutMillis` | `300000` | How long a step-up ceremony may stay open before it ends as `Expired`. 30 seconds to one hour. |
| `enrollTimeoutMillis` | `600000` | The same for enrollment. 30 seconds to one hour. |

The constructor throws `IllegalArgumentException` for an invalid value, so a
configuration mistake fails when your activity is created rather than in front
of a user.

Do not reuse a `frameToken`. Each launch needs a new one from your backend,
including a retry after `Cancelled` or `Expired`. Each new `frameToken` comes
with a new challenge or registration on your backend, which keeps the matching
`challengeId` or `registrationId` and uses it when your app sends the result.

### Checking your setup

`DaaSca.capabilities(context, config)` reports what this device and your app's
manifest support. It only reads the package manager, so you can call it before
each ceremony, and in a debug build to check your integration:

```kotlin
import android.content.Context
import android.util.Log
import com.circle.daa.sdk.sca.DaaSca
import com.circle.daa.sdk.sca.DaaScaConfig
import com.circle.daa.sdk.sca.DaaScaSurface

fun logScaSetup(
    context: Context,
    config: DaaScaConfig,
) {
    val capabilities = DaaSca.capabilities(context, config)
    if (capabilities.surface == DaaScaSurface.None) Log.w("Sca", "No supported browser can run the ceremony")
    if (!capabilities.callbackRegistered) Log.w("Sca", "redirectUri is not routed to DaaScaCallbackActivity")
    if (capabilities.callbackVerified == false) Log.w("Sca", "The App Link for redirectUri is not verified")
    if (capabilities.callbackTaskIsolated == false) Log.w("Sca", "DaaScaCallbackActivity needs taskAffinity=\"\"")
}
```

| Field | Meaning |
| --- | --- |
| `surface` | `AuthTab`, `CustomTab`, or `None` when no supported browser is installed, or when `redirectUri` is a custom scheme and no supported browser offers an Auth Tab. |
| `callbackRegistered` | Your manifest routes `redirectUri` to `DaaScaCallbackActivity`, declared `exported="true"`. |
| `callbackVerified` | Android has verified your app for the redirect host (Android 12 and later). `null` before Android 12 or for a custom scheme. Verification can take a while after a fresh install. |
| `callbackTaskIsolated` | `DaaScaCallbackActivity` is declared with `taskAffinity=""`. `null` if it is not declared. |
| `platformPasskeys` | The OS version supports browser passkeys. A hint only; the browser decides. |

### Error handling

A ceremony ends with one `DaaScaResult`:

| Result | Meaning | What to do |
| --- | --- | --- |
| `Completed` | The user finished the ceremony. | Send `response` to your backend unchanged. |
| `Cancelled` | The user closed the tab or declined, came back to the app without finishing, or your app launched another ceremony while this one was open. | Not an error. Offer a retry: your backend opens a **new** challenge or registration, and you launch with its new `frameToken`. |
| `Failed(Expired)` | The ceremony expired while open, or nothing came back within the timeout. | Your backend opens a new challenge or registration, replaces the ID it stored, and returns the new `frameToken`. Never reuse a `frameToken`. |
| `Failed(Unsupported)` | This device or app cannot run the ceremony. See `unsupportedReason` below. | Depends on the reason. |
| `Failed(AlreadyEnrolled)` | Enrollment only: the user already has a passkey. | Treat the user as enrolled and use step-up. |
| `Failed(Transport)` | The browser could not verify your App Link in time, usually because the device is offline. | Retry once with a new `frameToken`. If it persists, ask the user to check their connection. |
| `Failed(Protocol)` | Circle's page and this SDK version did not understand each other. | Retrying will not help. Update the SDK, and contact Circle if it persists. |

`Failed.message` is diagnostic text for your logs. Do not show it to users or
branch on it.

`Failed(Unsupported)` carries a `DaaScaUnsupportedReason`:

| `unsupportedReason` | Meaning | What to do |
| --- | --- | --- |
| `NoAllowedBrowser` | No [supported browser](#supported-browsers) is installed and enabled. | Ask the user to install or enable one (see below). |
| `CallbackNotRouted` | The ceremony needed a Custom Tab, and your manifest does not route `redirectUri` to an exported `DaaScaCallbackActivity`. | A bug in your app. Fix the manifest. |
| `AppLinkNotVerified` | The browser could not verify that your app owns the redirect host. | A setup problem. Check `assetlinks.json` and `autoVerify`. |
| `InsecureRedirect` | The redirect URI is a custom scheme, and the ceremony cannot keep it from other apps: a step-up, or an enrollment where no supported browser offers an Auth Tab. | Use an `https` App Link. |
| `PasskeyUnavailable` | The browser could not run the passkey prompt: no screen lock or usable authenticator, or the browser refused or failed it. Circle's page reports these the same way. | Offer your fallback, or ask the user to set a screen lock or try another supported browser. |

There is no "not enrolled" result. Your backend checks for a passkey before it
opens a challenge.

### Supported browsers

The ceremony runs only in these browsers, each checked by package name and
signing certificate:

- Google Chrome
- Samsung Internet
- Mozilla Firefox, Firefox Focus and Firefox Klar
- Microsoft Edge
- Brave
- DuckDuckGo
- Opera and Opera Mini
- Vivaldi
- Seznam

These are the stable, consumer releases of browsers that Android trusts to use
passkeys on behalf of websites. Beta and developer builds are not included. A
listed browser that cannot open a Custom Tab on a device is skipped there.

The list changes only with SDK releases. Among the installed ones, the SDK
prefers a browser that supports Auth Tab, then the user's default browser. If
none is installed, the result is `Unsupported` with `NoAllowedBrowser`, and
`capabilities().surface` is `None` beforehand. Suggested copy:

> To approve this, you need a supported browser such as Google Chrome, Samsung
> Internet, Firefox, Microsoft Edge, Brave, DuckDuckGo or Opera. Install or
> enable one of them, then try again.

### Known behavior

- **Returning to the app mid-ceremony.** If the user leaves the browser tab
  and opens your app from the launcher icon or the recent apps list, the
  ceremony can end as `Cancelled`. Retry with a new `frameToken`.
- **One ceremony at a time.** Launching while a ceremony is open ends the open
  one as `Cancelled` and does not start the new one. Disable the control that
  starts a ceremony until its result arrives.
- **An expired or used `frameToken`** cannot send the user back automatically.
  Circle's page tells the user to return to the app, and the result is
  `Cancelled`.
- Circle's ceremony page is currently in English.

### Security checklist

- **Keep the Circle API key on your backend.** The app needs only the
  `frameToken`.
- **Treat the `frameToken` as a secret.** Deliver it over your own
  authenticated channel. Do not log it or put it in a URL.
- **Relay `Completed.response` unchanged.** It is the exact text Circle
  verifies. Do not parse, re-serialize or re-encode it in the app.
- **Authenticate the app-to-backend hop.** The endpoints that receive a
  ceremony result must check that the signed-in user is the one the challenge
  or registration was opened for.
- **Do not show your own confirmation of what is being approved.** The user
  approves what Circle's page shows.
- **Use an `https` App Link,** with `autoVerify` and an `assetlinks.json` that
  lists only your app's certificates.
- **Do not log results.** `Completed` keeps `response` out of `toString()`;
  keep it out of your own logs too.

## Owner AuthKey

The SDK also contains the installation-scoped P-256 Owner AuthKey
(`DaaSecureKey`) and the validated device-authorization signing boundary used
for attested authentication. These are not yet approved for production use.
They expose no generic signing call: signing is reachable only through the
validated device-authorization and registration-authorization APIs.

- `DaaSecureKey`: a non-exportable Android Keystore P-256 key and ES256
  signing.
- `DaaRegistrationFlowKey` and `DaaSecureRandom`: per-attempt login
  primitives, which never enter the Keystore.
- `DaaPrepareReceiptSignature`: verify-only ES256 check of a Circle-signed
  receipt.

## Development

```bash
./gradlew build apiCheck   # compile, unit tests, Kotlin and Android lint, public API check
./gradlew ktlintFormat     # fix formatting
```

```
settings.gradle.kts        rootProject = daa-android-sdk; include(":sdk")
build.gradle.kts           Root Android/Kotlin build and plugin versions
sdk/
  build.gradle.kts         Android library, publishing, and test configuration
  api/sdk.api              The public API snapshot apiCheck compares against
  src/main/                Public API and internal implementations
  src/test/                JVM unit tests
  src/androidTest/         Instrumented tests (device or emulator)
```

## Support and security reporting

- Integration questions: contact your Circle representative.
- Bugs in this SDK: open a GitHub issue.
- Security vulnerabilities: do not file a public issue. Report them privately
  through Circle's [Vulnerability Disclosure Program](https://hackerone.com/circle-bbp).
  See [SECURITY.md](SECURITY.md).

## License

[Apache License 2.0](LICENSE)
