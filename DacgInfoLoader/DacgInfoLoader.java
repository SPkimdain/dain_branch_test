package com.fasoo.shelob.ev1.analysis.checker.dacg;

import com.fasoo.shelob.ev1.analysis.checker.dacg.iis.IisDacgInfo;
import com.fasoo.shelob.ev1.analysis.checker.dacg.npm.NpmDacgInfo;
import com.fasoo.shelob.ev1.analysis.checker.dacg.technote.TechnoteDacgInfo;
import com.fasoo.shelob.ev1.analysis.checker.dacg.wp.WpDacgInfo;
import com.fasoo.shelob.ev1.analysis.checker.dacg.zeroboard.ZeroboardDacgInfo;
import com.fasoo.shelob.ev1.util.ResourceUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * The class for loading the DACG information in the resources.
 * @author im_jh
 * @since 2018.12.04
 */
final class DacgInfoLoader {
    /** The logger for this loader **/
    private static final Logger LOGGER = LoggerFactory.getLogger(DacgInfoLoader.class);

    /** The relative DACG resources directory path from the package of the base class **/
    private static final String DACG_INFO_RESOURCE_PATH = "/";
    /** The base class to be used for loading resources **/
    private static final Class BASE_CLAZZ = DacgInfoLoader.class;

    /** The map consists of DACG checker id as a key and that information as a value. **/
    private Map<String, DacgInfoContainer> dacgInfoMap;

    /** The singleton instance of this loader **/
    public static final DacgInfoLoader INSTANCE = new DacgInfoLoader();

    private DacgInfoLoader() {
        this.dacgInfoMap = load();
    }

    /**
     * Load the DACG information in the resources and generate DacgInfoContainer instances.
     * @return the generated DacgInfoContainer map
     */
    private static Map<String, DacgInfoContainer> load() {
        Map<String, DacgInfoContainer> loaded = new HashMap<>();

        try {
            List<String> jsonResources = ResourceUtils.getResourceListing(BASE_CLAZZ,
                    ResourceUtils.toAbsResourcePath(BASE_CLAZZ, DACG_INFO_RESOURCE_PATH));
            jsonResources.stream().filter(dj -> dj.toLowerCase().endsWith(".json")) // Get only JSON files in the resource directory.
                    .map(DacgInfoLoader::parseDacgJson).flatMap(List::stream)       // Parse the JSON resource file
                    .forEach(dic -> loaded.put(dic.getId(), dic));                  // Put in the loaded DacgInfoContainer instances
        } catch (URISyntaxException | IOException e) {
            LOGGER.error("Failed to load the DACG resources : package - {}, path - {}",
                    BASE_CLAZZ.getPackage().getName(), DACG_INFO_RESOURCE_PATH, e);
        }

        return loaded;
    }

    /**
     * Parse the Dacg JSON string in the JSON resource file located in the resource path.
     * @param resourcePath the JSON resource file location
     * @return the created DacgInfoContainer instances by parsing
     */
    private static List<DacgInfoContainer> parseDacgJson(String resourcePath) {
        // Get the absolute resource path.
        String absPath = ResourceUtils.toAbsResourcePath(BASE_CLAZZ, resourcePath);
        try (InputStream is = BASE_CLAZZ.getClassLoader().getResourceAsStream(absPath)) {
            return parse(is);
        } catch (IOException ioe) {
            LOGGER.warn("Invalid InputStream of the DACG resource : {}", absPath, ioe);
        } catch (Exception e) {
            LOGGER.error("Invalid DACG Json file : {}", absPath, e);
        }
        return new ArrayList<>();
    }

    /**
     * Parse the JSON string gotten by given InputStream and create DacgInfoContainer instances.
     * The JSON format is referred the TEST resource : <b>com.fasoo.shelob.ev1.analysis.checker.dacg#dacg_info_test.json</b>
     * @param is the InputStream to be used for reading JSON string
     * @return the created DacgInfoContainer instances
     */
    private static List<DacgInfoContainer> parse(InputStream is) throws Exception {
        List<DacgInfoContainer> loadedList = new ArrayList<>();
        try {
            ObjectMapper mapper = new ObjectMapper();
            JsonNode read = mapper.readTree(is);
            // 'dacg' root object node
            JsonNode root = read.get("dacg");

            // 'npm' top object node
            JsonNode npmTop = root.get("npm");
            // 'checkers_meta_data' array node in 'npm'
            JsonNode npmMetaDataArrayNode = npmTop.get("checker_meta_data");
            for (JsonNode npmMetaData : npmMetaDataArrayNode) {
                // 'library' field
                String library = npmMetaData.get("library").textValue();
                // 'versionInterval' field
                String versionInterval = npmMetaData.get("versionInterval").textValue();
                // 'vulnerability' field
                String vulnerability = npmMetaData.get("vulnerability").textValue();
                // 'id' field
                String id = npmMetaData.get("id").textValue();

                // These values should be not empty.
                if (library.isEmpty() || versionInterval.isEmpty() || vulnerability.isEmpty() || id.isEmpty()) {
                    throw new Exception("Cannot create 'NpmDacgInfo' instance since there is no essential values : " +
                            "library - " + library + ", versionInterval - "+ versionInterval + ", vulnerability - " + vulnerability + ", id - " + id);
                } else {
                    // Create a new NpmDacgInfo instance and add in the list
                    loadedList.add(new NpmDacgInfo(library, versionInterval, vulnerability, id));
                }
            }

            // 'wp' top object node
            JsonNode wpTop = root.get("wp");
            // 'checkers_meta_data' array node in 'wp'
            JsonNode wpMetaDataArrayNode = wpTop.get("checker_meta_data");
            for(JsonNode wpMetaData : wpMetaDataArrayNode) {
                // 'target' field
                String target = wpMetaData.get("target").textValue();
                // 'name' field
                String name = wpMetaData.get("name").textValue();
                // 'vulnerability' field
                String vulnerability = wpMetaData.get("vulnerability").textValue();
                // 'versionInterval' field
                String versionInterval = wpMetaData.get("versionInterval").textValue();
                // 'id' field
                String id = wpMetaData.get("id").textValue();

                // These values should be not empty.
                if(target.isEmpty() || name.isEmpty() || vulnerability.isEmpty() || versionInterval.isEmpty() || id.isEmpty()) {
                    throw new Exception("Cannot create 'WpDacgInfo' instance since there is no essential values : " +
                            "target - " + target + ", name - " + name + ", vulnerability - " + vulnerability + ", versionInterval - " + versionInterval + ", id - " + id);
                } else {
                    // Create a new WpDacgInfo instance and add in the list
                    loadedList.add(new WpDacgInfo(target, name, vulnerability, versionInterval, id));
                }
            }

            // 'iis' top object node
            JsonNode iisTop = root.get("iis");
            // 'checkers_meta_data' array node in 'iis'
            JsonNode iisMetaDataArrayNode = iisTop.get("checker_meta_data");
            for(JsonNode iisMetaData : iisMetaDataArrayNode) {
                // 'target' field
                String target = iisMetaData.get("target").textValue();
                // 'name' field
                String name = iisMetaData.get("name").textValue();
                // 'vulnerability' field
                String vulnerability = iisMetaData.get("vulnerability").textValue();
                // 'versionInterval' field
                String versionInterval = iisMetaData.get("versionInterval").textValue();
                // 'id' field
                String id = iisMetaData.get("id").textValue();

                // These values should be not empty.
                if(target.isEmpty() || name.isEmpty() || vulnerability.isEmpty() || versionInterval.isEmpty() || id.isEmpty()) {
                    throw new Exception("Cannot create 'IisDacgInfo' instance since there is no essential values : " +
                            "target - " + target + ", name - " + name + ", vulnerability - " + vulnerability + ", versionInterval - " + versionInterval + ", id - " + id);
                } else {
                    // Create a new IisDacgInfo instance and add in the list
                    loadedList.add(new IisDacgInfo(target, name, vulnerability, versionInterval, id));
                }
            }

            // 'technote' top object node
            JsonNode technoteTop = root.get("technote");
            // 'checkers_meta_data' array node in 'technote'
            JsonNode technoteMetaDataArrayNode = technoteTop.get("checker_meta_data");
            for(JsonNode technoteMetaData : technoteMetaDataArrayNode) {
                // 'name' field
                String name = technoteMetaData.get("name").textValue();
                // 'vulnerability' field
                String vulnerability = technoteMetaData.get("vulnerability").textValue();
                // 'versionInterval' field
                String versionInterval = technoteMetaData.get("versionInterval").textValue();
                // 'id' field
                String id = technoteMetaData.get("id").textValue();

                // These values should be not empty.
                if(name.isEmpty() || vulnerability.isEmpty() || versionInterval.isEmpty() || id.isEmpty()) {
                    throw new Exception("Cannot create 'TechnoteDacgInfo' instance since there is no essential values : " +
                            "name - " + name + ", vulnerability - " + vulnerability + ", versionInterval - " + versionInterval + ", id - " + id);
                } else {
                    // Create a new TechnoteDacgInfo instance and add in the list
                    loadedList.add(new TechnoteDacgInfo(name, vulnerability, versionInterval, id));
                }
            }

            // 'zeroboard' top object node
            JsonNode zeroboardTop = root.get("zeroboard");
            // 'checkers_meta_data' array node in 'zeroboard'
            JsonNode zeroboardMetaDataArrayNode = zeroboardTop.get("checker_meta_data");
            for(JsonNode zeroboardMetaData : zeroboardMetaDataArrayNode) {
                // 'name' field
                String name = zeroboardMetaData.get("name").textValue();
                // 'vulnerability' field
                String vulnerability = zeroboardMetaData.get("vulnerability").textValue();
                // 'versionInterval' field
                String versionInterval = zeroboardMetaData.get("versionInterval").textValue();
                // 'id' field
                String id = zeroboardMetaData.get("id").textValue();

                // These values should be not empty.
                if(name.isEmpty() || vulnerability.isEmpty() || versionInterval.isEmpty() || id.isEmpty()) {
                    throw new Exception("Cannot create 'ZeroboardDacgInfo' instance since there is no essential values : " +
                            "name - " + name + ", vulnerability - " + vulnerability + ", versionInterval - " + versionInterval + ", id - " + id);
                } else {
                    // Create a new ZeroboardDacgInfo instance and add in the list
                    loadedList.add(new ZeroboardDacgInfo(name, vulnerability, versionInterval, id));
                }
            }
        } catch (IOException ioe) {
            LOGGER.warn("Cannot parse to convert JSON string to DacgInfoContainer by the InputStream.", ioe);
        }
        return loadedList;
    }

    /**
     * Get the DacgInfoContainer instances matched with one of the give checker identifiers.
     * @param checkerIds the checker identifiers to be gotten
     * @return the matched DacgInfoContainer instances
     */
    static List<DacgInfoContainer> getInfoList(List<String> checkerIds) {
        // Convert the checker identifiers to uppercase.
        List<String> upperIds = checkerIds.stream().map(String::toUpperCase).collect(Collectors.toList());
        // Find the DacgInfoContainers matched with one of the given checker identifiers.
        return INSTANCE.dacgInfoMap.keySet().stream().filter(k -> upperIds.contains(k.toUpperCase()))
                .map(INSTANCE.dacgInfoMap::get).collect(Collectors.toList());
    }

    /**
     * Get all DACG checker ids for testing.
     * todo Should be removed
     * @return the all DACG checker ids
     */
    static Set<String> getAllDacgCheckerIds() {
        return INSTANCE.dacgInfoMap.keySet();
    }
}