package com.security.tfa;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.qr.ZxingPngQrGenerator;
import dev.samstevens.totp.secret.DefaultSecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import dev.samstevens.totp.util.Utils;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

@Service
@Slf4j

public class TowFactorAuthenticationService {

    public String generateNewSecret(){
        return new DefaultSecretGenerator().generate();

    }


    public String generateQrCodeImageUri(String secret){

        QrData qrData=new QrData.Builder()
                .label("Abdelrahman Coding For Tow Factor Authentication ")
                .secret(secret)
                .issuer("Abdelrahman Coding")
                .algorithm(HashingAlgorithm.SHA1)
                .digits(6)
                .period(30)
                .build();

        QrGenerator qrGenerator= new ZxingPngQrGenerator();
        byte[] imageData= new byte[0];
        try {
            imageData=qrGenerator.generate(qrData);
        } catch (QrGenerationException e) {
            e.printStackTrace();
            log.error("Error While Generate QrCode");
        }
        return Utils.getDataUriForImage(imageData,qrGenerator.getImageMimeType());
    }


    public boolean isdOtpValid(String secret,String code){
        TimeProvider timeProvider=new SystemTimeProvider();
        CodeGenerator codeGenerator=new DefaultCodeGenerator();
        CodeVerifier codeVerifier =new DefaultCodeVerifier(codeGenerator,timeProvider);

        return codeVerifier.isValidCode(secret,code);
    }

    public boolean isdOtpNotValid(String secret,String code){
        return !this.isdOtpValid(secret,code);
    }
}
