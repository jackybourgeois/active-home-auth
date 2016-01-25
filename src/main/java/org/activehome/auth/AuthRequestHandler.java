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
import com.eclipsesource.json.JsonValue;
import org.activehome.com.Request;
import org.activehome.com.RequestCallback;
import org.activehome.com.error.*;
import org.activehome.com.error.Error;
import org.activehome.service.RequestHandler;
import org.activehome.tools.file.FileHelper;
import org.activehome.tools.file.TypeMime;
import org.activehome.context.data.UserInfo;

import java.util.UUID;

/**
 * @author Jacky Bourgeois
 * @version %I%, %G%
 */
public class AuthRequestHandler implements RequestHandler {

    protected final Request request;
    protected final Auth service;

    public AuthRequestHandler(Request request, Auth service) {
        this.request = request;
        this.service = service;
    }

    public void authenticate(String user, String pass, RequestCallback callback) {
        service.authenticate(user, pass, request.getEnviElem().get("api").toString(), callback);
    }

    public void checkToken(UUID token, RequestCallback callback) {
        UserInfo userInfo = service.checkToken(
                token, request.getEnviElem().get("api").toString());
        if (userInfo != null) {
            callback.success(userInfo);
        } else {
            callback.error(new Error(ErrorType.PERMISSION_DENIED, "Unrecognized or expired token."));
        }
    }

    public void register(final String userId,
                         final String pass,
                         final String household,
                         final String groups,
                         final String type,
                         final RequestCallback callback) {
        if (request.getEnviElem().get("api") == null) {
            boolean success = service.register(userId, pass, household, groups, type);
            if (success) {
                callback.success(true);
            } else {
                callback.error(new Error(ErrorType.METHOD_ERROR, "Failed to register " + userId));
            }
        } else {
            callback.error(new Error(ErrorType.PERMISSION_DENIED, "Registration cannot be done through an API."));
        }
    }

    public JsonValue html() {
        JsonObject wrap = new JsonObject();
        wrap.add("name", "auth-view");
        wrap.add("url", service.getId() + "/auth-view.html");
        wrap.add("title", "Active Home Authentication");
        wrap.add("description", "Active Home Authentication");

        JsonObject json = new JsonObject();
        json.add("wrap", wrap);
        return json;
    }

    public JsonValue red(String redirectUrl) {
        JsonObject wrap = new JsonObject();
        wrap.add("name", "auth-view");
        wrap.add("url", "/" + service.getId() + "/auth-view.html");
        wrap.add("title", "Active Home Authentication");
        wrap.add("description", "Active Home Authentication");

        JsonObject json = new JsonObject();
        json.add("wrap", wrap);
        return json;
    }

    public JsonValue file(String str) {
        String content = FileHelper.fileToString(str, getClass().getClassLoader());
        if (str.compareTo("auth-view.html") == 0) content = content.replaceAll("\\$\\{id\\}", service.getId());
        JsonObject json = new JsonObject();
        json.add("content", content);
        json.add("mime", TypeMime.valueOf(str.substring(str.lastIndexOf(".") + 1, str.length())).getDesc());
        return json;
    }

}
