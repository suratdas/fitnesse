package fitnesseMain;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.PropertyAccessor;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import fitnesse.ConfigurationParameter;
import fitnesse.ContextConfigurator;
import fitnesse.FitNesse;
import fitnesse.FitNesseContext;
import fitnesse.Updater;
import fitnesse.components.PluginsClassLoaderFactory;
import fitnesse.reporting.ExitCodeListener;
import fitnesse.socketservice.PlainServerSocketFactory;
import fitnesse.socketservice.SslParameters;
import fitnesse.socketservice.SslServerSocketFactory;
import fitnesse.updates.WikiContentUpdater;
import fitnesse.wiki.PathParser;

import java.io.*;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.BindException;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.LogManager;
import java.util.logging.Logger;

import static fitnesse.ConfigurationParameter.*;

public class FitNesseMain {
  private static final Logger LOG = Logger.getLogger(FitNesseMain.class.getName());

  private final ExitCodeListener exitCodeListener = new ExitCodeListener();
  public static String licenseServerAddress = "http://localhost/licenses";
  private static final String programVersion = "0.0.1";
  private static List<Integer> allowedPorts = new ArrayList<>();
  public static String licenseIdUsed = "";
  public static String keyUsed = "";
  public static int fitnessePortUsed = 0;

  private static HttpResponse<Map<String, Object>> generateLicenseInServer() throws IOException, InterruptedException, URISyntaxException {
    String key = getANewEncryptionKey();
    Map<String, String> bodyMap = getMapWithSystemDetails(key);
    bodyMap.put("source", "program");
    bodyMap.put("key", key);
    ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
    String jsonBody = objectMapper.writeValueAsString(bodyMap);
    return sendRequestAndReturnResponse(licenseServerAddress, jsonBody);
  }

  //  public static Map<String, Object> callLicenseServerFromLibrary(String licenseIdUsed, String keyUsed, int port, String area, String libraryVersion) {
  public static Map<String, Object> callLicenseServerFromLibrary(String value, String area, String libraryVersion) {
    String[] values = value.split("::");
    licenseServerAddress = values[0].trim();
    licenseIdUsed = values[1].trim();
    keyUsed = values[2].trim();
    int port = Integer.parseInt(values[3].trim());

    Map<String, Object> valueToReturn = new HashMap<>();
    try {
      HttpResponse httpResponse = callLicenseServerForValidity("library", licenseIdUsed, keyUsed, port, area, libraryVersion);
      HashMap<String, Object> body = getHashMapFromResponseBodyString(httpResponse.body().toString());
      if (body.containsKey("error")) {
        throw new Exception(body.get("error").toString());
      }
      if (!body.containsKey("isValid")) {
        throw new Exception("Something went wrong while processing...");
      }
      valueToReturn.put("isValid", body.get("isValid"));
      if (body.containsKey("message"))
        valueToReturn.put("message", body.get("message"));
    } catch (Exception exception) {
      valueToReturn.put("isValid", false);
      valueToReturn.put("message", exception.getMessage());
      printSurroundedByDelimiter(exception.getMessage());
    }
    return valueToReturn;
  }

  private static HttpResponse callLicenseServerForValidityFromProgram(String licenseId, String encryptionKey) throws IOException, URISyntaxException, InterruptedException {
    return callLicenseServerForValidity("program", licenseId, encryptionKey, -1, null, null);
  }

  private static HttpResponse callLicenseServerForValidity(String type, String licenseId, String encryptionKey, int port, String area, String libraryVersion) throws IOException, URISyntaxException, InterruptedException {
    Map<String, String> bodyMap = getMapWithSystemDetails(encryptionKey);
    bodyMap.put("source", type);
    if (type.equals("program")) {
      bodyMap.put("allowedProgramVersion", programVersion);
    } else {
      if (libraryVersion != null)
        bodyMap.put("allowedLibraryVersion", libraryVersion);
    }
    bodyMap.put("licenseId", licenseId);
    if (port != -1)
      bodyMap.put("port", String.valueOf(port));
    if (area != null)
      bodyMap.put("area", area);
    ObjectMapper objectMapper = new ObjectMapper();
    objectMapper.setVisibility(PropertyAccessor.FIELD, JsonAutoDetect.Visibility.ANY);
    String jsonBody = objectMapper.writeValueAsString(bodyMap);
    String address = licenseServerAddress + "/" + licenseId + "/validity";
    return sendRequestAndReturnResponse(address, jsonBody);
  }

  private static Map<String, String> getMapWithSystemDetails(String encryptionKey) {
    String command = null;
    String osString = System.getProperty("os.name").toLowerCase();
    /* Some references
        https://cloud.google.com/compute/docs/instances/get-uuid#windows-cmd.exe
        wmic path win32_computersystemproduct get uuid
        # cat /sys/class/dmi/id/product_uuid
        ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $(NF-1)}'
    */
    if (Arrays.stream((new String[]{"nix", "nux", "aix"})).anyMatch(e -> osString.contains(e))) {
      command = "hostnamectl";
    } else if (osString.contains("win")) {
      command = "systeminfo && wmic bios get serialnumber && wmic csproduct get UUID";
    } else if (osString.contains("mac")) {
      command = "system_profiler SPSoftwareDataType && system_profiler SPSoftwareDataType";
    }
    String bodyString = callCommandLine(command);
    bodyString += System.lineSeparator() + "whoami: " + callCommandLine("whoami");
    bodyString += System.lineSeparator() + "java.version: " + System.getProperty("java.version");
    bodyString += System.lineSeparator() + "user.country: " + System.getProperty("user.country");
    SecretKeySpec secretKeySpec = new SecretKeySpec(encryptionKey.getBytes(StandardCharsets.UTF_8), "AES");
    IvParameterSpec ivParameterSpec = new IvParameterSpec(encryptionKey.getBytes(StandardCharsets.UTF_8));

    try {
      Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
      cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
      byte[] bytes = cipher.doFinal(bodyString.getBytes());
      String encryptedString = new String(Base64.getEncoder().encode(bytes));
      Map<String, String> bodyMap = new HashMap<>();
      bodyMap.put("details", encryptedString);
      return bodyMap;
    } catch (Exception exception) {
      printSurroundedByDelimiter("There was an error. Please contact the license provider.");
      System.exit(1);
    }
    return null;
  }

  protected static Map<String, Object> isValidLicense(String licenseId) {
    if (licenseId == null || licenseId.isEmpty()) {
      return populateFailureHashMap("You have not passed the licenseId.");
    }
    try {
      keyUsed = getEncryptionKeyFromLicenseId(licenseId);
      HttpResponse httpResponse = callLicenseServerForValidityFromProgram(licenseId, keyUsed);
      if (httpResponse.statusCode() != 200) {
        String message = getHashMapFromResponseBodyString(httpResponse.body().toString()).get("message").toString();
        return populateFailureHashMap(message);
      }
      HashMap<String, Object> responseMap = getHashMapFromResponseBodyString(httpResponse.body().toString());
      boolean isValid = Boolean.parseBoolean(responseMap.get("isValid").toString());
      if (!isValid) {
        String message = getHashMapFromResponseBodyString(httpResponse.body().toString()).get("message").toString();
        return populateFailureHashMap(message);
      }
      if (isValid && responseMap.containsKey("allowedPorts")) {
        allowedPorts = (List<Integer>) responseMap.get("allowedPorts");
      }
      HashMap<String, Object> valueToReturn = new HashMap<>();
      valueToReturn.put("isValid", true);
      return valueToReturn;
    } catch (Exception exception) {
      String message = (exception.getMessage() == null) ? "Could not determine license validity." : exception.getMessage();
      return populateFailureHashMap(message);
    }
  }

  private static HashMap<String, Object> populateFailureHashMap(String errorMessage) {
    HashMap<String, Object> valueToReturn = new HashMap<>();
    valueToReturn.put("isValid", false);
    valueToReturn.put("message", errorMessage);
    return valueToReturn;
  }

  private static String callCommandLine(String command) {
    try {
      Process process = Runtime.getRuntime().exec(command);
      process.waitFor();
      BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(process.getInputStream()));
      String line = "";
      StringBuilder bodyString = new StringBuilder();
      while ((line = bufferedReader.readLine()) != null) {
        bodyString.append(line).append(System.lineSeparator());
      }
      return bodyString.toString();
    } catch (Exception ex) {
      return ex.getMessage();
    }
  }

  private static HttpResponse sendRequestAndReturnResponse(String licenseServerAddress, String jsonBody) throws IOException, InterruptedException, URISyntaxException {
    HttpRequest httpRequest = HttpRequest.newBuilder()
      .uri(new URI(licenseServerAddress))
      .headers("Content-Type", "application/json")
      .headers("Accept", "application/json")
      .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
      .build();
    return HttpClient
      .newBuilder()
      .build()
      .send(httpRequest, HttpResponse.BodyHandlers.ofString());
  }

  private static String getANewEncryptionKey() throws IOException, InterruptedException, URISyntaxException {
    return getKey(licenseServerAddress + "/new-key");
  }

  private static String getEncryptionKeyFromLicenseId(String licenseId) throws IOException, InterruptedException, URISyntaxException {
    return getKey(licenseServerAddress + "/" + licenseId + "/key");
  }

  private static String getKey(String url) throws IOException, InterruptedException, URISyntaxException {
    HttpRequest httpRequest = HttpRequest.newBuilder()
      .uri(new URI(url))
      .headers("Accept", "application/json")
      .GET()
      .build();
    HttpResponse<String> httpResponse = HttpClient
      .newBuilder()
      .build()
      .send(httpRequest, HttpResponse.BodyHandlers.ofString());
    if (httpResponse.statusCode() != 200) {
      try {
        printSurroundedByDelimiter(getHashMapFromResponseBodyString(httpResponse.body()).get("error").toString());
      } catch (Throwable ex) {
        printSurroundedByDelimiter(httpResponse.body());
      }
      System.exit(0);
    }
    HashMap<String, Object> responseMap = getHashMapFromResponseBodyString(httpResponse.body());
    if (responseMap.containsKey("key")) {
      return responseMap.get("key").toString();
    }
    throw new EOFException("Could not retrieve the key.");
  }

  private static HashMap getHashMapFromResponseBodyString(String body) throws JsonProcessingException {
    ObjectMapper objectMapper = new ObjectMapper();
    return objectMapper.readValue(body, HashMap.class);
  }

  private static void printSurroundedByDelimiter(String text) {
    String[] lines = text.split(System.lineSeparator());
    AtomicInteger maxLength = new AtomicInteger();
    Arrays.asList(lines).forEach(e -> {
      if (e.length() > maxLength.get())
        maxLength.set(e.length());
    });
    String delimiterChar = "#";
    for (int i = 0; i < maxLength.get(); i++) {
      delimiterChar += "#";
    }
    delimiterChar += "#";
    System.out.println(System.lineSeparator());
    System.out.println(delimiterChar);
    System.out.println(" " + text);
    System.out.println(delimiterChar);
  }


  public static void main(String[] args) throws IOException, URISyntaxException, InterruptedException {
    boolean isReadFromFile = false;
    System.out.println("Using version " + programVersion);
    try {
      File file = new File("license.properties");
      if (file.exists()) {
        System.out.println("Reading from the provided license file...");
        String textsFromFile = Files.readString(Path.of(file.getPath()));
        String[] lines = textsFromFile.split(System.lineSeparator());
        for (String line : lines) {
          if (line.startsWith("license=")) {
            licenseIdUsed = line.split("license=")[1].trim();
            isReadFromFile = true;
          } else if (line.startsWith("licenseServerAddress=")) {
            licenseServerAddress = line.split("licenseServerAddress=")[1].trim();
          }
        }
      }
    } catch (Exception exception) {
      printSurroundedByDelimiter(exception.getMessage());
      System.exit(0);
    }
    /*
    boolean validBodyFromProgram = Boolean.parseBoolean(isValidLicense("7f82e48e-fd69-356c-b942-8100ba934da0").get("isValid").toString());
    //boolean invalidBodyFromProgram = isValidLicense("6f82e48e-fd69-356c-b942-8100ba934da0");
    Map<String, Object> validBodyLibrary = callLicenseServerFromLibrary(licenseServerAddress + "::7f82e48e-fd69-356c-b942-8100ba934da0::99q0x7gapiFU8Sxb:: 9090", "API", "0.0.1");
    Map<String, Object> invalidLibraryVersion = callLicenseServerFromLibrary(licenseServerAddress + "::7f82e48e-fd69-356c-b942-8100ba934da0::99q0x7gapiFU8Sxb::9090", "API", "0.0.2");
    Map<String, Object> invalidLicenseKeyLibrary = callLicenseServerFromLibrary(licenseServerAddress + "::6f82e48e-fd69-356c-b942-8100ba934da0::99q0x7gapiFU8Sxb:: 9090", "API", "0.0.1");
    Map<String, Object> invalidEncryptionKeyLibrary = callLicenseServerFromLibrary(licenseServerAddress + "::7f82e48e-fd69-356c-b942-8100ba934da0::89q0x7gapiFU8Sxb:: 9090", "API", "0.0.1");
    Map<String, Object> invalidPortLibrary = callLicenseServerFromLibrary(licenseServerAddress + "::7f82e48e-fd69-356c-b942-8100ba934da0::99q0x7gapiFU8Sxb::8081", "API", "0.0.1");
    Map<String, Object> invalidAreaLibrary = callLicenseServerFromLibrary(licenseServerAddress + "::7f82e48e-fd69-356c-b942-8100ba934da0::99q0x7gapiFU8Sxb::9090", "InvalidArea", "0.0.1");
    //*/
    if (!isReadFromFile) {
      if (args.length == 0 || !isLicenseParameter(args)) {
        printSurroundedByDelimiter("If you have a license, run the program using argument as \"license=<your_license_key>\"" +
          System.lineSeparator() + " To generate a license, run this program by giving argument as \"generateLicense\"");
        System.exit(0);
      } else if (args[0].startsWith("generateLicense") || args[0].startsWith("gl")) {
        try {
          HttpResponse response = generateLicenseInServer();
          HashMap<String, Object> map = getHashMapFromResponseBodyString(response.body().toString());
          String valueToPrint = map.containsKey("result") ? map.get("result").toString() : map.get("error").toString();
          printSurroundedByDelimiter(valueToPrint);
          System.exit(0);
        } catch (Exception ex) {
          printSurroundedByDelimiter("There was some problem connecting to the server. Details: " + ex.getMessage());
          System.exit(0);
        }
      }
      licenseIdUsed = args[0].split("=")[1].trim();
    }
    Map<String, Object> licenseResult = isValidLicense(licenseIdUsed);
    boolean isValidLicense = Boolean.parseBoolean(licenseResult.get("isValid").toString());
    if (!isValidLicense) {
      printSurroundedByDelimiter(licenseResult.get("message").toString());
      System.exit(0);
    }
    if (isLicenseParameter(args)) {
      args = Arrays.stream(args).skip(1).toArray(String[]::new);
    }
    /*
    File file = new File("");
    BasicFileAttributes basicFileAttributes = Files.readAttributes((Paths.get(file.getPath()), BasicFileAttributes.class);
    long value = ChronoUnit.DAYS.between(basicFileAttributes.lastAccessTime().toInstant(), Instant.now());
    if (value > 1) {
      if(!isValidLicense(Files.readString(file.getPath())))
        System.out.println("License is not valid");
      System.exit(0);
    }

    //If file does not exist
    if(!file.exists())
      //
    //*/
    Arguments arguments = null;
    try {
      arguments = new Arguments(args);
    } catch (IllegalArgumentException e) {
      Arguments.printUsage();
      exit(1);
    }
    Integer exitCode;
    try {
      exitCode = new FitNesseMain().launchFitNesse(arguments);
    } catch (Exception e) {
      LOG.log(Level.SEVERE, "Error while starting the FitNesse", e);
      exitCode = 1;
    }
    if (exitCode != null) {
      exit(exitCode);
    }
  }

  private static boolean isLicenseParameter(String[] args) {
    if (args.length == 0)
      return false;
    return args[0].startsWith("generateLicense") || args[0].startsWith("gl") || args[0].startsWith("license=");
  }

  protected static void exit(int exitCode) {
    System.exit(exitCode);
  }

  public Integer launchFitNesse(Arguments arguments) throws Exception {
    ContextConfigurator contextConfigurator = ContextConfigurator.systemDefaults();
    contextConfigurator = contextConfigurator.updatedWith(System.getProperties());
    contextConfigurator = contextConfigurator.updatedWith(ConfigurationParameter.loadProperties(new File(arguments.getConfigFile(contextConfigurator))));
    contextConfigurator = arguments.update(contextConfigurator);

    return launchFitNesse(contextConfigurator);
  }

  public Integer launchFitNesse(ContextConfigurator contextConfigurator) throws Exception {
    configureLogging("verbose".equalsIgnoreCase(contextConfigurator.get(LOG_LEVEL)));

    ClassLoader classLoader = PluginsClassLoaderFactory.getClassLoader(contextConfigurator.get(ConfigurationParameter.ROOT_PATH));
    contextConfigurator.withClassLoader(classLoader);

    if (contextConfigurator.get(COMMAND) != null) {
      contextConfigurator.withTestSystemListener(exitCodeListener);
    }

    FitNesseContext context = contextConfigurator.makeFitNesseContext();

    if (!establishRequiredDirectories(context.getRootPagePath())) {
      LOG.severe("FitNesse cannot be started...");
      LOG.severe("Unable to create FitNesse root directory in " + context.getRootPagePath());
      LOG.severe("Ensure you have sufficient permissions to create this folder.");
      return 1;
    }

    logStartupInfo(context);

    if (update(context)) {
      LOG.info("**********************************************************");
      LOG.info("Files have been updated to a new version.");
      LOG.info("Please read the release notes on ");
      LOG.info("http://localhost:" + context.port + "/FitNesse.ReleaseNotes");
      LOG.info("to find out about the new features and fixes.");
      LOG.info("**********************************************************");
    }

    if ("true".equalsIgnoreCase(contextConfigurator.get(INSTALL_ONLY))) {
      return null;
    }

    try {
      return launch(context, classLoader);
    } catch (BindException e) {
      LOG.severe("Port " + context.port + " is already in use.");
      LOG.severe("Use the -p <port#> command line argument to use a different port.");
      return 1;
    }

  }

  private boolean establishRequiredDirectories(String rootPagePath) {
    return establishDirectory(new File(rootPagePath)) &&
      establishDirectory(new File(rootPagePath, PathParser.FILES));
  }

  private static boolean establishDirectory(File path) {
    return path.exists() || path.mkdir();
  }

  private boolean update(FitNesseContext context) throws IOException {
    if (!"true".equalsIgnoreCase(context.getProperty(OMITTING_UPDATES.getKey()))) {
      Updater updater = new WikiContentUpdater(context);
      return updater.update();
    }
    return false;
  }

  private Integer launch(FitNesseContext context, ClassLoader classLoader) throws Exception {
    if (!"true".equalsIgnoreCase(context.getProperty(INSTALL_ONLY.getKey()))) {
      String command = context.getProperty(COMMAND.getKey());
      if (command != null) {
        String output = context.getProperty(OUTPUT.getKey());
        executeSingleCommand(context.fitNesse, command, output);

        return exitCodeListener.getFailCount();
      } else {
        //Verify if port is licensed on this machine.
        if (!allowedPorts.contains(context.port)) {
          printSurroundedByDelimiter(String.format("Error : You are trying to run on port %d. Please contact license provider to add this port to your existing license.", context.port));
          System.exit(0);
        } else {
          fitnessePortUsed = context.port;
        }
        if ("true".equalsIgnoreCase(context.getProperty(LOCALHOST_ONLY.getKey()))) {
          LOG.info("Starting program on port: " + context.port + " (loopback only)");
        } else {
          LOG.info("Starting program on port: " + context.port);
        }
        ServerSocket serverSocket = createServerSocket(context, classLoader);
        context.fitNesse.start(serverSocket);
      }
    }
    return null;
  }

  private ServerSocket createServerSocket(FitNesseContext context, ClassLoader classLoader) throws IOException {
    String protocol = context.getProperty(FitNesseContext.WIKI_PROTOCOL_PROPERTY);
    boolean useHTTPS = (protocol != null && protocol.equalsIgnoreCase("https"));
    String clientAuth = context.getProperty(FitNesseContext.SSL_CLIENT_AUTH_PROPERTY);
    final boolean sslClientAuth = (clientAuth != null && clientAuth.equalsIgnoreCase("required"));
    final String sslParameterClassName = context.getProperty(FitNesseContext.SSL_PARAMETER_CLASS_PROPERTY);
    if ("true".equalsIgnoreCase(context.getProperty(LOCALHOST_ONLY.getKey()))) {
      return (useHTTPS
        ? new SslServerSocketFactory(sslClientAuth, SslParameters.createSslParameters(sslParameterClassName, classLoader))
        : new PlainServerSocketFactory()).createLocalOnlyServerSocket(context.port);
    } else {
      return (useHTTPS
        ? new SslServerSocketFactory(sslClientAuth, SslParameters.createSslParameters(sslParameterClassName, classLoader))
        : new PlainServerSocketFactory()).createServerSocket(context.port);
    }
  }

  private void executeSingleCommand(FitNesse fitNesse, String command, String outputFile) throws Exception {

    LOG.info("Executing command: " + command);

    OutputStream os;

    boolean outputRedirectedToFile = outputFile != null;

    if (outputRedirectedToFile) {
      LOG.info("Command Output redirected to: " + outputFile);
      os = new FileOutputStream(outputFile);
    } else {
      os = System.out;
    }

    fitNesse.executeSingleCommand(command, os);
    fitNesse.stop();

    if (outputRedirectedToFile) {
      os.close();
    }
  }

  private void logStartupInfo(FitNesseContext context) {
    // This message is on standard output for backward compatibility with Jenkins Fitnesse plugin.
    // (ConsoleHandler of JUL uses standard error output for all messages).
    System.out.println("Welcome to the fully integrated standalone wiki and acceptance testing framework.");
/*
    LOG.info("root page: " + context.getRootPage());
    LOG.info("logger: " + (context.logger == null ? "none" : context.logger.toString()));
    LOG.info("authenticator: " + context.authenticator);
    LOG.info("page factory: " + context.pageFactory);
    LOG.info("page theme: " + context.pageFactory.getTheme());
 */
  }

  public void configureLogging(boolean verbose) {
    if (loggingSystemPropertiesDefined()) {
      return;
    }

    InputStream in = FitNesseMain.class.getResourceAsStream((verbose ? "verbose-" : "") + "logging.properties");
    try {
      LogManager.getLogManager().readConfiguration(in);
    } catch (Exception e) {
      LOG.log(Level.SEVERE, "Log configuration failed", e);
    } finally {
      if (in != null) {
        try {
          in.close();
        } catch (IOException e) {
          LOG.log(Level.SEVERE, "Unable to close Log configuration file", e);
        }
      }
    }
    LOG.finest("Configured verbose logging");
  }

  private boolean loggingSystemPropertiesDefined() {
    return System.getProperty("java.util.logging.config.class") != null ||
      System.getProperty("java.util.logging.config.file") != null;
  }

}
