package com.danielfrak.code.keycloak.providers.rest.remote;

import java.util.Optional;

/**
 * Interface to be implemented by Legacy user provider.
 */
public interface LegacyUserService {

    /**
     * Find user by email address.
     *
     * @param email email address to search user by.
     * @return Optional of legacy user.
     */
    Optional<LegacyUser> findByEmail(String email);

    /**
     * Find user by username.
     *
     * @param username username to search user by.
     * @return Optional of legacy user.
     */
    Optional<LegacyUser> findByUsername(String username);

    /**
     * Find user by phone number.
     *
     * @param phone phone number to search user by.
     * @return Optional of legacy user.
     */
    Optional<LegacyUser> findByPhone(String phone) ;

    /**
     * Validate given password in legacy user provider.
     *
     * @param username username to validate password for.
     * @param password the password to validate.
     * @return true if password is valid.
     */
    boolean isPasswordValid(String username, String password);

    /**
     * Creates a new LegacyUser based on the provided username.
     * @param username The username intended for the LegacyUser creation.
     * @return An Optional containing the LegacyUser if successfully created,
     *         or an empty Optional otherwise.
     */
    Optional<LegacyUser> createLegacyUser(String username) ;
}
