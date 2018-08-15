package com.topjohnwu.snet;

import android.app.Activity;
import android.content.Context;
import android.os.Bundle;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import com.google.android.gms.common.ConnectionResult;
import com.google.android.gms.common.api.GoogleApiClient;
import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi.AttestationResponse;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;

import org.json.JSONException;
import org.json.JSONObject;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.security.SecureRandom;

public class SafetyNetHelper implements InvocationHandler, GoogleApiClient.ConnectionCallbacks,
        GoogleApiClient.OnConnectionFailedListener{

    public static final int CAUSE_SERVICE_DISCONNECTED = 0x01;
    public static final int CAUSE_NETWORK_LOST = 0x02;
    public static final int RESPONSE_ERR = 0x04;
    public static final int CONNECTION_FAIL = 0x08;

    public static final int BASIC_PASS = 0x10;
    public static final int CTS_PASS = 0x20;

    public static final int SNET_EXT_VER = 10;

    private Activity mActivity;
    private Object callback;

    SafetyNetHelper(Activity activity, Object cb) {
        mActivity = activity;
        callback = cb;
    }

    /* Override ISafetyNetHelper.getVersion */
    private int getVersion() {
        return SNET_EXT_VER;
    }

    /* Override ISafetyNetHelper.attest */
    private void attest() {
        // Connect Google Service
        GoogleApiClient mGoogleApiClient = new GoogleApiClient.Builder(mActivity)
                .addApi(SafetyNet.API)
                .addOnConnectionFailedListener(this)
                .addConnectionCallbacks(this)
                .build();
        mGoogleApiClient.connect();
    }

    @Override
    public Object invoke(Object o, Method method, Object[] args) {
        if (method.getName().equals("attest")) {
            attest();
        } else if (method.getName().equals("getVersion")) {
            return getVersion();
        }
        return null;
    }

    private void invokeCallback(int code) {
        Class<?> clazz = callback.getClass();
        try {
            clazz.getMethod("onResponse", int.class).invoke(callback, code);
        } catch (Exception ignored) {}
    }

    @Override
    public void onConnectionSuspended(int i) {
        invokeCallback(i);
    }

    @Override
    public void onConnectionFailed(ConnectionResult result) {
        invokeCallback(CONNECTION_FAIL);
    }

    @Override
    public void onConnected(Bundle bundle) {
        // not used but to keep compile work, copy once
        
        // Create nonce
        byte[] nonce = new byte[24];
        new SecureRandom().nextBytes(nonce);

        // Call SafetyNet
        Context c = mActivity.getApplicationContext();
        SafetyNet.getClient(c).attest(nonce, "AIzaSyBCxiTQobFqW1EyYA5TiqLYN6hci_xSQVU")
                .addOnSuccessListener(mActivity,
                        new OnSuccessListener<AttestationResponse>() {
                            @Override
                            public void onSuccess(AttestationResponse response) {
                                int code = 0;
                                try {
                                    String jsonStr = new String(Base64.decode(
                                            response.getJwsResult().split("\\.")[1], Base64.DEFAULT));
                                    JSONObject json = new JSONObject(jsonStr);
                                    code |= json.getBoolean("ctsProfileMatch") ? CTS_PASS : 0;
                                    code |= json.getBoolean("basicIntegrity") ? BASIC_PASS : 0;
                                } catch (JSONException e) {
                                    code = RESPONSE_ERR;
                                }
                                invokeCallback(code);
                            }
                        })
                .addOnFailureListener(mActivity, new OnFailureListener() {
                    @Override
                    public void onFailure(@NonNull Exception e) {
                        // An error occurred while communicating with the service.
                        Log.d("MagiskSafetynet", "Error: " + e.getMessage());
                        invokeCallback(RESPONSE_ERR);
                    }
                });
    }

}
