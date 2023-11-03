package com.example;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
public class ResourceControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void homePage_returns401UnauthorizedResponse() throws Exception {
        this.mockMvc
                .perform(get("/home").header("Authorization", "bearer zzz"))
                .andDo(print())
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"An error occurred while attempting to decode the Jwt: Invalid JWT serialization: Missing dot delimiter(s)\", error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\""));
    }
}
