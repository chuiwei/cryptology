package com.toughpear.cryptology.exception;

public class CryptException extends RuntimeException {
    public CryptException(Exception e) {
        super(e);
    }
}
