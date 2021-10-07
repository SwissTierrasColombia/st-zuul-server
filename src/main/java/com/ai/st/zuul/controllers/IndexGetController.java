package com.ai.st.zuul.controllers;

import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
public class IndexGetController {

    @GetMapping(value = "/", produces = MediaType.APPLICATION_JSON_VALUE)
    @ResponseBody
    public Map<String, String> health() {
        HashMap<String, String> map = new HashMap<>();
        map.put("status", "st_on");
        return map;
    }

}
