package com.topjohnwu.magisk.asyncs;

import android.app.Activity;
import android.support.annotation.NonNull;
import android.util.Base64;
import android.util.Log;

import com.google.android.gms.safetynet.SafetyNet;
import com.google.android.gms.safetynet.SafetyNetApi;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;
import com.google.android.gms.tasks.Task;
import com.google.android.gms.tasks.Tasks;
import com.topjohnwu.magisk.Data;
import com.topjohnwu.magisk.utils.Topic;

import org.json.JSONException;
import org.json.JSONObject;

import java.io.File;
import java.security.SecureRandom;

import static com.topjohnwu.magisk.utils.ISafetyNetHelper.BASIC_PASS;
import static com.topjohnwu.magisk.utils.ISafetyNetHelper.CTS_PASS;
import static com.topjohnwu.magisk.utils.ISafetyNetHelper.RESPONSE_ERR;

public class CheckSafetyNet extends ParallelTask<Void, Void, Exception> {

    public static final File dexPath =
            new File(Data.MM().getFilesDir().getParent() + "/snet", "snet.apk");

    public CheckSafetyNet(Activity activity) {
        super(activity);
    }

    private void dyload() throws Exception {
        // Create nonce
        byte[] nonce = new byte[24];
        new SecureRandom().nextBytes(nonce);

        // Call SafetyNet
        Task<SafetyNetApi.AttestationResponse> t = SafetyNet.getClient(getActivity()).attest(nonce, "AIzaSyBCxiTQobFqW1EyYA5TiqLYN6hci_xSQVU")
                .addOnSuccessListener(new OnSuccessListener<SafetyNetApi.AttestationResponse>() {
                    @Override
                    public void onSuccess(SafetyNetApi.AttestationResponse response) {
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
                        Topic.publish(false, Topic.SNET_CHECK_DONE, code);
                    }
                })
                .addOnFailureListener(new OnFailureListener() {
                    @Override
                    public void onFailure(@NonNull Exception e) {
                        // An error occurred while communicating with the service.
                        Log.d("MagiskSafetynet", "Error: " + e.getMessage());
                        Topic.publish(false, Topic.SNET_CHECK_DONE, 0x04);
                    }
                });
        Tasks.await(t);
    }

    @Override
    protected Exception doInBackground(Void... voids) {
        try {
            try {
                dyload();
            } catch (Exception e) {
                dyload();
            }
        } catch (Exception e) {
            return e;
        }

        return null;
    }

    @Override
    protected void onPostExecute(Exception e) {
        if (e != null) {
            e.printStackTrace();
            Topic.publish(false, Topic.SNET_CHECK_DONE, -1);
        }
        super.onPostExecute(e);
    }
}
