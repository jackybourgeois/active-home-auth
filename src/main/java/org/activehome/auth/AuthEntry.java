package org.activehome.auth;

/*
 * #%L
 * Active Home :: Auth
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2016 Active Home Project
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


import org.activehome.context.data.UserInfo;

import java.util.UUID;

/**
 * @author Jacky Bourgeois
 * @version %I%, %G%
 */
public class AuthEntry {

    private UUID token;
    private UserInfo userInfo;
    private String api;
    private long expirationDate;

    public AuthEntry(UUID token, UserInfo userInfo, String api, long expirationDate) {
        this.token = token;
        this.userInfo = userInfo;
        this.api = api;
        this.expirationDate = expirationDate;
    }

    public UUID getToken() {
        return token;
    }

    public UserInfo getUserInfo() {
        return userInfo;
    }

    public String getApi() {
        return api;
    }

    public long getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(long time) {
        expirationDate = time;
    }
}
