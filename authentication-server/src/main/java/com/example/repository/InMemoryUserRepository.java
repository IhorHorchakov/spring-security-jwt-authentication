package com.example.repository;

import com.example.model.User;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Repository
public class InMemoryUserRepository implements UserRepository {
    private final Map<Integer, User> storage = new HashMap<>();

    public InMemoryUserRepository() {
        // pass = johndoe
        this.storage.put(0, new User(0, "johndoe@gmail.com", "$2a$10$yTgzyw/4E1pnLGVFkmNyoeWXajIvdBJ/YGgK53Lc9PL0A3vudShNa"));
        // pass = fairyprincess
        this.storage.put(1, new User(1, "fairyprincess@gmail.com", "$2a$10$.GDRfH5hI/CZwpfpeIFphOY6AvI6RSAHvI6MYzRH9y8u3rp13SXsi"));
    }

    @Override
    public Optional<User> getByUsername(String username) {
        return storage.values().stream().filter(user -> username.equals(user.getUsername())).findFirst();
    }
}
