package com.warxim.jxpathrce.controller;

import lombok.Value;
import org.apache.commons.jxpath.FunctionLibrary;
import org.apache.commons.jxpath.JXPathContext;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * REST controller with two endpoints:
 * <ul>
 *     <li>{@code /vulnerable-example?path=[path]}</li>
 *     <li>{@code /secure-example?path=[path]}</li>
 * </ul>
 */
@RestController
public class ProofOfConceptController {

    /**
     * Example data object
     */
    @Value
    public static class Person {
        String name;
        String website;
    }

    /**
     * Hardcoded person object for PoC
     */
    private final Person person = new Person( "Michal Valka", "warxim.com");

    /**
     * Following code will allow the attacker to execute code.
     * <p>For example, attacker can send query <b>?path=java.lang.System.exit(42)</b>, which will stop the application.</p>
     */
    @GetMapping("vulnerable-example")
    public Object getVulnerableExample(
            @RequestParam(defaultValue = "/") String path
    ) {
        // Create path context for person object
        var pathContext = JXPathContext.newContext(person);

        // Vulnerable getValue call
        return pathContext.getValue(path);
    }

    /**
     * Following code will disable functions by removing the default functions from context.
     * <p>Note: No functions will work in path string!</p>
     */
    @GetMapping("secure-example")
    public Object getSecureExample(
            @RequestParam(defaultValue = "/") String path
    ) {
        // Create path context for person object
        var pathContext = JXPathContext.newContext(person);

        // Set empty function library
        pathContext.setFunctions(new FunctionLibrary());

        // getValue will throw org.apache.commons.jxpath.JXPathFunctionNotFoundException
        return pathContext.getValue(path);
    }

}
