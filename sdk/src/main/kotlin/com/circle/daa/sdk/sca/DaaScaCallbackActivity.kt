/*
 * Copyright (c) 2026, Circle Internet Group, Inc. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.circle.daa.sdk.sca

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import com.circle.daa.sdk.sca.internal.ScaCallback
import com.circle.daa.sdk.sca.internal.ScaCeremonyActivity
import com.circle.daa.sdk.sca.internal.ScaPendingStoreFile

/**
 * Receives the ceremony page's redirect when the ceremony runs in a Custom Tab, and hands
 * it to the ceremony in flight. (In an Auth Tab the browser returns the redirect to the
 * SDK directly and this activity is not involved.) The SDK uses a Custom Tab only for an
 * `https` redirect URI, so this activity only ever needs the `https` filter below.
 *
 * The SDK does not declare this activity; the host app does, because only the host app
 * knows its redirect URI. Declare it exported, with a single intent filter matching
 * [DaaScaConfig.redirectUri] exactly, and `autoVerify` so Android verifies the App Link
 * against the `assetlinks.json` on your domain. Give it an empty `taskAffinity`, so a
 * callback it drops never brings the app's task, and the ceremony waiting in it, to the
 * front:
 *
 * ```xml
 * <activity
 *     android:name="com.circle.daa.sdk.sca.DaaScaCallbackActivity"
 *     android:exported="true"
 *     android:excludeFromRecents="true"
 *     android:taskAffinity=""
 *     android:theme="@android:style/Theme.Translucent.NoTitleBar">
 *     <intent-filter android:autoVerify="true">
 *         <action android:name="android.intent.action.VIEW" />
 *         <category android:name="android.intent.category.DEFAULT" />
 *         <category android:name="android.intent.category.BROWSABLE" />
 *         <data android:scheme="https" android:host="app.example.com" android:path="/sca/callback" />
 *     </intent-filter>
 * </activity>
 * ```
 *
 * It holds no state and trusts nothing it receives. Being exported, any app can start it,
 * so before doing anything it checks that the intent is a `VIEW` with a callback URI within
 * the size limit, and that the URI carries the `state` of the ceremony in flight. Anything
 * else is dropped without touching the ceremony: a forged callback can neither complete a
 * ceremony nor end one the user is still in.
 */
public class DaaScaCallbackActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val data = intent?.takeIf { it.action == Intent.ACTION_VIEW }?.data
        val callback = data?.toString()?.takeIf { it.length <= ScaCallback.MAX_CALLBACK_CHARS }
        if (callback != null && ScaPendingStoreFile.pending(this).accepts(callback)) {
            // Only the URI crosses over: no extras, flags or component the sender chose.
            startActivity(
                Intent(this, ScaCeremonyActivity::class.java)
                    .setData(data)
                    .addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP),
            )
        }
        finish()
    }
}
