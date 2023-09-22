package com.danielfrak.code.keycloak.providers.rest;

import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUser;
import com.danielfrak.code.keycloak.providers.rest.remote.LegacyUserService;
import com.danielfrak.code.keycloak.providers.rest.remote.UserModelFactory;
import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.policy.PasswordPolicyManagerProvider;
import org.keycloak.policy.PolicyError;
import org.keycloak.storage.UserStoragePrivateUtil;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Stream;

/**
 * Provides legacy user migration functionality
 */
public class LegacyProvider implements UserStorageProvider,
        UserLookupProvider,
        UserQueryProvider,
        CredentialInputUpdater,
        CredentialInputValidator,
        UserRegistrationProvider
{


    private static final Logger LOG = Logger.getLogger(LegacyProvider.class);
    private static final Set<String> supportedCredentialTypes = Collections.singleton(PasswordCredentialModel.TYPE);
    private final KeycloakSession session;
    private final LegacyUserService legacyUserService;
    private final UserModelFactory userModelFactory;
    private final ComponentModel model;

    public LegacyProvider(KeycloakSession session, LegacyUserService legacyUserService,
                          UserModelFactory userModelFactory, ComponentModel model) {
        this.session = session;
        this.legacyUserService = legacyUserService;
        this.userModelFactory = userModelFactory;
        this.model = model;
    }

    private UserModel getUserModel(RealmModel realm, String username, Supplier<Optional<LegacyUser>> user) {
        return user.get()
//                .filter(u -> {
//                    // Make sure we're not trying to migrate users if they have changed their username
//                    LOG.warnf("Searching for: %s", username);
//                    boolean duplicate = userModelFactory.isDuplicateUserId(u, realm);
//                    if (duplicate) {
//                        LOG.warnf("User with the same user id already exists: %s", u.getId());
//                    }
//                    return !duplicate;
//                })

                .map(u -> {
                            // Make sure we're not trying to migrate users if they have changed their username
                            LOG.warnf("Searching for: %s", username);
                            boolean duplicate = userModelFactory.isDuplicateUserId(u, realm);
                            if (duplicate) {
                                LOG.warnf("User with the same user id already exists: %s", u.getId());
                                return userModelFactory.getUserById( u,realm);
                            } else {
                                LOG.warnf("User with the same user id created : %s", u.getId());
                                return userModelFactory.create(u, realm);
                            }
                        }
                )
                .orElseGet(() -> {
                    LOG.warnf("User not found in external repository: %s", username);
                    if(session == null) {
                        LOG.info("session is null");
                        return null;
                    }
                    else {
                        try {
                            LOG.info("searching in local storage");
                            var us = UserStoragePrivateUtil.userLocalStorage(session).getUserByUsername(realm, username);
                            LOG.info("user from local "+us);
                            return us;
                        } catch (Exception e){
                            LOG.error("error",e);
                            return  null;
                        }
                    }

                });
    }


//    private UserModel getUserModel(RealmModel realm, String username, Supplier<Optional<LegacyUser>> user) {
//        return user.get()
//                .filter(u -> {
//                    // Make sure we're not trying to migrate users if they have changed their username
//                    LOG.warnf("Searching for: %s", username);
//                    boolean duplicate = userModelFactory.isDuplicateUserId(u, realm);
//                    if (duplicate) {
//                        LOG.warnf("User with the same user id already exists: %s", u.getId());
//                    }
//                    return !duplicate;
//                })
//                .map(u -> userModelFactory.create(u, realm))
//                .orElseGet(() -> {
//                    LOG.warnf("User not found in external repository: %s", username);
//                    return null;
//                });
//    }

    @Override
    public boolean isValid(RealmModel realmModel, UserModel userModel, CredentialInput input) {
        if (!supportsCredentialType(input.getType())) {
            return false;
        }

        var userIdentifier = getUserIdentifier(userModel);

        if (!legacyUserService.isPasswordValid(userIdentifier, input.getChallengeResponse())) {
            return false;
        }

        if (passwordDoesNotBreakPolicy(realmModel, userModel, input.getChallengeResponse())) {
            userModel.credentialManager().updateCredential(input);
        } else {
            addUpdatePasswordAction(userModel, userIdentifier);
        }

        return true;
    }

    private String getUserIdentifier(UserModel userModel) {
        var userIdConfig = model.getConfig().getFirst(ConfigurationProperties.USE_USER_ID_FOR_CREDENTIAL_VERIFICATION);
        var useUserId = Boolean.parseBoolean(userIdConfig);
        return useUserId ? userModel.getId() : userModel.getUsername();
    }

    private boolean passwordDoesNotBreakPolicy(RealmModel realmModel, UserModel userModel, String password) {
        PasswordPolicyManagerProvider passwordPolicyManagerProvider = session.getProvider(
                PasswordPolicyManagerProvider.class);
        PolicyError error = passwordPolicyManagerProvider
                .validate(realmModel, userModel, password);

        return error == null;
    }

    private void addUpdatePasswordAction(UserModel userModel, String userIdentifier) {
        if (updatePasswordActionMissing(userModel)) {
            LOG.infof("Could not use legacy password for user %s due to password policy." +
                            " Adding UPDATE_PASSWORD action.",
                    userIdentifier);
            userModel.addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        }
    }

    private boolean updatePasswordActionMissing(UserModel userModel) {
        return userModel.getRequiredActionsStream()
                .noneMatch(s -> s.contains(UserModel.RequiredAction.UPDATE_PASSWORD.name()));
    }

    @Override
    public boolean supportsCredentialType(String s) {
        return supportedCredentialTypes.contains(s);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realmModel, UserModel userModel, String s) {
        return false;
    }

    @Override
    public void close() {
        // Not needed
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        severFederationLink(user);
        return false;
    }

    private void severFederationLink(UserModel user) {
        LOG.info("Severing federation link for " + user.getUsername());
        String link = user.getFederationLink();
        if (link != null && !link.isBlank()) {
            user.setFederationLink(null);
        }
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        // Not needed
    }

    @Override
    public Stream<String> getDisableableCredentialTypesStream(RealmModel realmModel, UserModel userModel) {
        return Stream.empty();
    }

    @Override
    public UserModel getUserById(RealmModel realmModel, String s) {
        throw new UnsupportedOperationException("User lookup by id not implemented");
    }

    @Override
    public UserModel getUserByUsername(RealmModel realmModel, String username) {
        return getUserModel(realmModel, username, () -> legacyUserService.findByUsername(username));
    }

    @Override
    public UserModel getUserByEmail(RealmModel realmModel, String email) {
        return getUserModel(realmModel, email, () -> legacyUserService.findByEmail(email));
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        return Stream.empty();
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
            Stream<UserModel> localStream = UserStoragePrivateUtil.userLocalStorage(session).searchForUserByUserAttributeStream(realm, attrName, attrValue);
            List<UserModel> localList = localStream.toList();
            if (!localList.isEmpty()) {
                return localList.stream();
            } else {
                return Stream.of(getUserModel(realm, attrValue, () -> legacyUserService.findByPhone(attrValue)))
                        .filter(Objects::nonNull);
            }

//        }

    }


    @Override
    public UserModel addUser(RealmModel realm, String username) {
        var legacyUser = legacyUserService.createLegacyUser(username);
        var userModel = getUserByUsername(realm,username);
        severFederationLink(userModel);
        return userModel;
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        return false;
    }
}
