package org.igor_klimov.auth;

import com.google.common.collect.Lists;
import org.igor_klimov.security.ApplicationUserRole;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

import static org.igor_klimov.security.ApplicationUserRole.*;

@Repository("fake")
public class FakeApplicationUserDaoService implements ApplicationUserDao{

    private final PasswordEncoder encoder;

    @Autowired
    public FakeApplicationUserDaoService(PasswordEncoder encoder) {
        this.encoder = encoder;
    }


    @Override
    public Optional<ApplicationUser> selectApplicationUserByUsername(String username) {
        return getApplicationUsers().stream()
                .filter(u -> username.equals(u.getUsername()))
                .findFirst();
    }

    private List<ApplicationUser> getApplicationUsers(){
        List<ApplicationUser> applicationUsers = Lists.newArrayList(
                new ApplicationUser(
                        "mikesmith",
                        encoder.encode("password"),
                        STUDENT.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true

                ),
                 new ApplicationUser(
                         "linda",
                         encoder.encode("password123"),
                         ADMIN.getGrantedAuthorities(),
                         true,
                         true,
                         true,
                         true
                 ),
                new ApplicationUser(
                        "tom",
                        encoder.encode("password123"),
                        ADMINTRAINEE.getGrantedAuthorities(),
                        true,
                        true,
                        true,
                        true
                )
        );
        return applicationUsers;
    }
}
