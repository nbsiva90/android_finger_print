package com.example.sivanatarajanbalasubramania.myapplication;

import android.Manifest;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.os.CancellationSignal;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.design.widget.FloatingActionButton;
import android.support.design.widget.Snackbar;
import android.support.v4.app.ActivityCompat;
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import android.support.v7.app.AppCompatActivity;
import android.support.v7.widget.Toolbar;
import android.view.View;
import android.view.Menu;
import android.view.MenuItem;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.Cipher;

public class MainActivity extends AppCompatActivity implements View.OnClickListener{

    private TextView mTextView;
    private Button mBtnClick;

    private FingerprintManager mFingerPrintManager;
    private KeyguardManager mKeyGuardManager;

    private FingerprintManager.CryptoObject mCryptoObject;
    private KeyStore mkeyStore;


    private static String KEY_NAME = "finger_print_key";
    private Context mContext;


    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        init();

    }

    private void init(){
        initUI();
        initRefs();

        if(checkFingerprintEnabled()){
            Toast.makeText(mContext, "All Set for Authentication", Toast.LENGTH_SHORT).show();
        }else{
            generateKey();
            mCryptoObject = new FingerprintManager.CryptoObject(generateCipher());
            Toast.makeText(mContext, "Init", Toast.LENGTH_SHORT).show();
        }
    }

    private void initRefs(){
        mContext = getApplicationContext();

        mFingerPrintManager = (FingerprintManager)
                getSystemService(FINGERPRINT_SERVICE);

        mKeyGuardManager = (KeyguardManager)
                getSystemService(KEYGUARD_SERVICE);
    }
    private void initUI(){
        mTextView = (TextView) findViewById(R.id.mtextview);
        mBtnClick = (Button) findViewById(R.id.btnClick);
        mBtnClick.setOnClickListener(this);
    }

    private boolean checkFingerPrintPermission(){
        if(ActivityCompat.checkSelfPermission(mContext, Manifest.permission.USE_FINGERPRINT)
                == PackageManager.PERMISSION_GRANTED){
            return true;
        }else{
            return false;
        }
    }

    private boolean checkFingerprintEnabled(){
        if(!checkFingerPrintPermission()){
            mTextView.setText("Permission not granted");
           return false;
        }

        if(!mFingerPrintManager.isHardwareDetected()){
            mTextView.setText("Hardware not detected");
            return false;
        }

        if(!mFingerPrintManager.hasEnrolledFingerprints()){
            mTextView.setText("Has not finger print enrolled");
            return false;
        }

        if(!mKeyGuardManager.isKeyguardSecure()){
            mTextView.setText("Key Guard Not Secure");
            return false;
        }

        return true;
    }

    private void generateKey(){
        try {
            mkeyStore = KeyStore.getInstance("AndroidKeyStore");

            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, "AndroidKeyStore");

            mkeyStore.load(null);

            keyGenerator.init( new
                    KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setUserAuthenticationRequired(true)
                    .build());

            keyGenerator.generateKey();

        }catch (KeyStoreException
                | NoSuchAlgorithmException
                | NoSuchProviderException
                | CertificateException
                | IOException
                | InvalidAlgorithmParameterException exception){
            exception.printStackTrace();
        }
    }

    private Cipher generateCipher(){
        try {
            Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_RSA);

            SecretKey key = (SecretKey) mkeyStore.getKey(KEY_NAME,
                    null);
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher;
        }
        catch (NoSuchAlgorithmException
                | NoSuchPaddingException
                | InvalidKeyException
                | UnrecoverableKeyException
                | KeyStoreException exc) {
            exc.printStackTrace();
        }
        return null;
    }

    @Override
    public void onClick(View view) {
        if (view.getId() == R.id.btnClick) {
            try {
                mFingerPrintManager.authenticate(mCryptoObject, new CancellationSignal(), 0,
                        new FingerprintManager.AuthenticationCallback() {
                                @Override
                                public void onAuthenticationError(int errorCode, CharSequence errString) {
                                    super.onAuthenticationError(errorCode, errString);
                                    mTextView.setText("Error " + errorCode +" " +errString);

                                }

                                @Override
                                public void onAuthenticationHelp(int helpCode, CharSequence helpString) {
                                    super.onAuthenticationHelp(helpCode, helpString);
                                }

                                @Override
                                public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                                    super.onAuthenticationSucceeded(result);
                                    mTextView.setText("Success");
                                }

                                @Override
                                public void onAuthenticationFailed() {
                                    super.onAuthenticationFailed();
                                    mTextView.setText("Error Failed");
                                }
                            },
                        null);

            } catch (SecurityException exec) {
                exec.printStackTrace();
            }
        }
    }
}
