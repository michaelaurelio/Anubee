// SPDX-License-Identifier: GPL-2.0
package dev.anubee.moddemoapp;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;

// Launcher shim only -- the actual demo sequence runs in DemoService, a
// foreground service. See DemoService's header for why a plain background
// thread on this Activity isn't enough (this device's OEM freezer suspends
// backgrounded apps regardless of held wake locks; a foreground service
// with an active notification is the standard exemption).
public class DemoActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        startForegroundService(new Intent(this, DemoService.class));
    }
}
