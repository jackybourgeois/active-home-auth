package org.activehome.auth;

/*
 * #%L
 * Active Home :: Auth
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2016 org.activehome
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the 
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public 
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/gpl-3.0.html>.
 * #L%
 */


import com.eclipsesource.json.JsonObject;
import org.activehome.com.Notif;
import org.activehome.com.Request;
import org.activehome.com.RequestCallback;
import org.activehome.com.error.*;
import org.activehome.com.error.Error;
import org.activehome.context.data.ComponentProperties;
import org.activehome.context.data.DataPoint;
import org.activehome.service.Service;
import org.activehome.service.RequestHandler;
import org.activehome.tools.Util;
import org.activehome.context.data.UserInfo;
import org.kevoree.annotation.ComponentType;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Date;
import java.util.HashMap;
import java.util.Properties;
import java.util.UUID;

/**
 * @author Jacky Bourgeois
 * @version %I%, %G%
 */
@ComponentType
public class Auth extends Service {

    private HashMap<UUID, AuthEntry> tokenMap;

    public Auth() {
        tokenMap = new HashMap<>();
    }

    @Override
    protected RequestHandler getRequestHandler(Request request) {
        return new AuthRequestHandler(request, this);
    }

    @Override
    public void modelUpdated() {
        if (isFirstModelUpdate()) {
            sendRequest(new Request(getFullId(), getNode() + ".http", getCurrentTime(),
                    "addHandler", new Object[]{"/auth", getFullId(), false}), null);
        }
        super.modelUpdated();
    }

    public void authenticate(final String userId,
                             final String pass,
                             final String api,
                             final RequestCallback callback) {
        Request ctxReq = new Request(getFullId(), getNode() + ".context", getCurrentTime(),
                "getLastData", new Object[]{new Object[]{"user." + userId + ".pass"}});
        sendRequest(ctxReq, new RequestCallback() {
            @Override
            public void success(Object obj) {
                if (obj instanceof JsonObject) {
                    JsonObject ctxRep = (JsonObject) obj;
                    if (ctxRep.isObject()) {
                        String encPass = new DataPoint(ctxRep.asObject().get("user." + userId + ".pass").asObject()).getValue();
                        if (!encPass.equals("")) {
                            UUID token = check(pass, encPass);
                            if (token != null) {
                                setUserInfo(userId, token, api, callback);
                            }
                        }
                    }
                }
            }

            @Override
            public void error(Error error) {
                logError(error.toString());
                callback.error(new Error(ErrorType.PERMISSION_DENIED,
                        "Unknown user and password."));
            }
        });
    }

    private void setUserInfo(String userId, UUID token, String api, RequestCallback callback) {
        String user = "user." + userId;
        String[] metric = new String[]{user + ".groups", user + ".household", user + ".type"};
        Request ctxReq = new Request(getFullId(), getNode() + ".context", getCurrentTime(),
                "getLastData", new Object[]{metric});
        sendRequest(ctxReq, new RequestCallback() {
            @Override
            public void success(Object obj) {
                if (obj instanceof JsonObject) {
                    JsonObject ctxRep = (JsonObject) obj;
                    if (ctxRep.isObject()) {
                        String[] groups = new DataPoint(ctxRep.asObject().get(user + ".groups").asObject()).getValue().split(",");
                        String household = new DataPoint(ctxRep.asObject().get(user + ".household").asObject()).getValue();
                        String userType = new DataPoint(ctxRep.asObject().get(user + ".type").asObject()).getValue();
                        if (groups[0].compareTo("") != 0 && !household.equals("") && !userType.equals("")) {
                            UserInfo userInfo = new UserInfo(userId, groups, household, userType);
                            AuthEntry authEntry = new AuthEntry(token, userInfo, api, new Date().getTime() + HOUR);
                            tokenMap.put(token, authEntry);
                            startComponent(authEntry, callback);
                        }
                    }
                }
            }

            @Override
            public void error(Error error) {
                logError(error.toString());
                callback.error(new Error(ErrorType.PERMISSION_DENIED,
                        "Unknown user and password."));
            }
        });
    }

    public void startComponent(AuthEntry authEntry, RequestCallback callback) {
        UserInfo userInfo = authEntry.getUserInfo();
        ComponentProperties cp = new ComponentProperties(userInfo.getUserType(),
                userInfo.getId(), new JsonObject(), new String[]{getNode()});
        Request req = new Request(getFullId(), userInfo.getHousehold() + ".linker",
                getCurrentTime(), "startComponent", new Object[]{cp, userInfo});
        sendRequest(req, new RequestCallback() {
            public void success(Object result) {
                callback.success(authEntry.getToken());
            }

            public void error(Error result) {
                callback.error(new Error(ErrorType.START_ERROR,
                        "Unable to start the manager for this user."));
            }
        });
    }

    /**
     * Check pass and return a token if access granted
     *
     * @param pass
     * @param encPass
     * @return
     */
    private UUID check(final String pass,
                       final String encPass) {
        try {
            Properties prop = Util.loadProperties(System.getProperty("activehome.home") + "/encKey.properties");
            String key = prop.getProperty("encKey");
            // Create key and cipher
            Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");

            // now convert the string to byte array
            // for decryption
            byte[] bb = new byte[encPass.length()];
            for (int i = 0; i < encPass.length(); i++) {
                bb[i] = (byte) encPass.charAt(i);
            }
            // decrypt the pass and compare
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            if (pass.compareTo(new String(cipher.doFinal(bb))) == 0) {
                return UUID.randomUUID();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public String encrypt(String pass) {
        Properties prop = Util.loadProperties(System.getProperty("activehome.home") + "/encKey.properties");
        String key = prop.getProperty("encKey");
        try {
            // Create key and cipher
            Key aesKey = new SecretKeySpec(key.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES");
            // encrypt the text
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            byte[] encrypted = cipher.doFinal(pass.getBytes());
            StringBuilder sb = new StringBuilder();
            for (byte b : encrypted) {
                sb.append((char) b);
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        return null;
    }

    public UserInfo checkToken(final UUID token,
                               final String api) {
        if (tokenMap.containsKey(token)) {
            AuthEntry ae = tokenMap.get(token);
            if (ae.getExpirationDate() > new Date().getTime()
                    && ae.getApi().equals(api)) {
                ae.setExpirationDate(new Date().getTime() + HOUR);
                return ae.getUserInfo();
            } else {
                tokenMap.remove(token);
            }
        }
        return null;
    }

    public boolean register(final String userId,
                            final String pass,
                            final String household,
                            final String groups,
                            final String type) {
        long ts = getCurrentTime();
        DataPoint passDP = new DataPoint("user." + userId + ".pass", ts, encrypt(pass));
        DataPoint householdDP = new DataPoint("user." + userId + ".household", ts, household);
        DataPoint groupsDP = new DataPoint("user." + userId + ".groups", ts, groups);
        DataPoint typeDP = new DataPoint("user." + userId + ".type", ts, type);
        logInfo("Register: send notif to context");
        sendNotif(new Notif(getFullId(), getNode() + ".context", ts,
                new DataPoint[]{passDP, householdDP, groupsDP, typeDP}));
        return true;
    }
}
