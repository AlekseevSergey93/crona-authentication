package com.cronagroup.authentication.user.service;

import com.cronagroup.authentication.common.error.ApiException;
import com.cronagroup.authentication.common.error.DependencyUnavailableException;
import com.cronagroup.authentication.common.security.AuthenticatedUser;
import com.cronagroup.authentication.user.api.CurrentUserResponse;
import com.cronagroup.authentication.user.domain.User;
import com.cronagroup.authentication.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class CurrentUserServiceTest {

    private UserRepository userRepository;
    private ObjectProvider<UserRepository> userRepositoryProvider;
    private CurrentUserService service;

    @BeforeEach
    void setUp() {
        userRepository = mock(UserRepository.class);
        userRepositoryProvider = mock(ObjectProvider.class);
        when(userRepositoryProvider.getIfAvailable()).thenReturn(userRepository);
        service = new CurrentUserService(userRepositoryProvider);
    }

    @Test
    void returnsOnlyCurrentUserIdAndEmail() {
        User user = User.create("user@example.com", "hash");
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        CurrentUserResponse response = service.get(
                new AuthenticatedUser(user.getId(), UUID.randomUUID())
        );

        assertThat(response.id()).isEqualTo(user.getId());
        assertThat(response.email()).isEqualTo("user@example.com");
    }

    @Test
    void rejectsMissingAuthenticationOrDeletedUser() {
        assertThatThrownBy(() -> service.get(null))
                .isInstanceOf(ApiException.class);

        UUID userId = UUID.randomUUID();
        when(userRepository.findById(userId)).thenReturn(Optional.empty());
        assertThatThrownBy(() -> service.get(new AuthenticatedUser(userId, UUID.randomUUID())))
                .isInstanceOf(ApiException.class);
    }

    @Test
    void mapsMissingRepositoryToDependencyUnavailable() {
        when(userRepositoryProvider.getIfAvailable()).thenReturn(null);

        assertThatThrownBy(() -> service.get(new AuthenticatedUser(UUID.randomUUID(), UUID.randomUUID())))
                .isInstanceOf(DependencyUnavailableException.class);
    }
}
