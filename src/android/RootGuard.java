package com.rootguard.detection;

import android.os.Build;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/**
 * Local, best-effort Android compromise detection.
 *
 * Status:
 * 0 = SAFE
 * 1 = COMPROMISED
 * 2 = UNKNOWN
 *
 * Legacy checkSecurity() intentionally maps:
 *
 * SAFE        -> 0
 * COMPROMISED -> 1
 * UNKNOWN     -> 1
 *
 * Therefore the existing Cordova JavaScript code can continue using:
 *
 * if (result === 1) {
 *     // Security Alert
 * }
 *
 * High-assurance device integrity should additionally be validated
 * server-side using Play Integrity.
 */
public final class RootGuard extends CordovaPlugin {

    private static final int SAFE = 0;
    private static final int COMPROMISED = 1;
    private static final int UNKNOWN = 2;

    private static final int SOCKET_TIMEOUT_MS = 100;
    private static final int MAX_MAP_LINES = 20000;
    private static final int MAX_FDS = 512;
    private static final int MAX_TASKS = 512;
    private static final int MAX_TCP_LINES = 256;
    private static final int MAX_PROTOCOL_PORTS = 8;

    private enum State {
        DETECTED,
        CLEAR,
        UNAVAILABLE
    }

    private enum Strength {
        HIGH,
        MEDIUM
    }

    private static final class Signal {

        final String id;
        final String category;
        final State state;
        final Strength strength;

        Signal(
                String id,
                String category,
                State state,
                Strength strength
        ) {
            this.id = id;
            this.category = category;
            this.state = state;
            this.strength = strength;
        }
    }

    private static final class Assessment {

        final int status;
        final List<Signal> signals;
        final List<String> unknownReasons;

        Assessment(
                int status,
                List<Signal> signals,
                List<String> unknownReasons
        ) {
            this.status = status;
            this.signals = signals;
            this.unknownReasons = unknownReasons;
        }
    }

    @Override
    public boolean execute(
            String action,
            JSONArray args,
            CallbackContext callback
    ) throws JSONException {

        if (!"checkSecurity".equals(action)
                && !"checkSecurityStatus".equals(action)
                && !"checkSecurityDetailed".equals(action)) {

            return false;
        }

        cordova.getThreadPool().execute(() -> {

            Assessment assessment;

            try {

                assessment = assess();

            } catch (Throwable ignored) {

                List<String> unknownReasons = new ArrayList<>();
                unknownReasons.add("assessment_exception");

                assessment = new Assessment(
                        UNKNOWN,
                        new ArrayList<>(),
                        unknownReasons
                );
            }

            /*
             * Existing API.
             *
             * SAFE        -> 0
             * COMPROMISED -> 1
             * UNKNOWN     -> 1
             *
             * This makes the application fail closed.
             */
            if ("checkSecurity".equals(action)) {

                callback.success(
                        assessment.status == SAFE ? 0 : 1
                );

            } else if ("checkSecurityStatus".equals(action)) {

                /*
                 * Detailed numeric status:
                 *
                 * 0 = SAFE
                 * 1 = COMPROMISED
                 * 2 = UNKNOWN
                 */
                callback.success(assessment.status);

            } else {

                callback.success(toJson(assessment));
            }
        });

        return true;
    }

    /**
     * Main assessment.
     */
    private Assessment assess() {

        List<Signal> signals = new ArrayList<>();

        signals.add(checkRootArtifacts());
        signals.add(checkSuOnPath());
        signals.add(checkBuildProvenance());
        signals.add(checkProcessMaps());
        signals.add(checkFileDescriptors());
        signals.add(checkThreadNames());
        signals.add(checkFridaProtocol());

        int high = countDetected(signals, Strength.HIGH);
        int medium = countDetected(signals, Strength.MEDIUM);

        boolean criticalUnavailable =
                criticalChecksUnavailable(signals);

        List<String> unknownReasons = new ArrayList<>();

        int status;

        /*
         * Strong evidence:
         *
         * Any HIGH signal means compromised.
         */
        if (high > 0) {

            status = COMPROMISED;

        /*
         * Two independent MEDIUM signals also mean compromised.
         */
        } else if (medium >= 2) {

            status = COMPROMISED;

        } else {

            if (medium == 1) {
                unknownReasons.add("single_medium_signal");
            }

            if (criticalUnavailable) {
                unknownReasons.add("critical_check_unavailable");
            }

            /*
             * If a critical local check cannot be performed,
             * don't claim the device is definitely clean.
             */
            if (!unknownReasons.isEmpty()) {

                status = UNKNOWN;

            } else {

                status = SAFE;
            }
        }

        return new Assessment(
                status,
                signals,
                unknownReasons
        );
    }

    /**
     * Root artifact detection.
     */
    private Signal checkRootArtifacts() {

        String[] paths = {

                "/system/app/Superuser.apk",

                "/system/bin/su",
                "/system/xbin/su",
                "/system/bin/.ext/.su",

                "/system/usr/we-need-root/su-backup",

                "/sbin/su",
                "/su/bin/su",

                "/sbin/.magisk",

                "/cache/magisk.log",

                "/data/adb/magisk",
                "/data/adb/ksu",
                "/data/adb/ap"
        };

        try {

            for (String path : paths) {

                if (new File(path).exists()) {

                    return new Signal(
                            "root_artifact",
                            "root",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }
            }

            return new Signal(
                    "root_artifact",
                    "root",
                    State.CLEAR,
                    Strength.HIGH
            );

        } catch (SecurityException ignored) {

            return new Signal(
                    "root_artifact",
                    "root",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }
    }

    /**
     * Detect executable su in PATH.
     */
    private Signal checkSuOnPath() {

        String path = System.getenv("PATH");

        if (path == null || path.length() == 0) {

            return new Signal(
                    "su_path",
                    "root",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }

        try {

            for (String directory : path.split(":")) {

                if (directory == null || directory.length() == 0) {
                    continue;
                }

                File candidate = new File(directory, "su");

                if (candidate.isFile() && candidate.canExecute()) {

                    return new Signal(
                            "su_path",
                            "root",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }
            }

            return new Signal(
                    "su_path",
                    "root",
                    State.CLEAR,
                    Strength.HIGH
            );

        } catch (SecurityException ignored) {

            return new Signal(
                    "su_path",
                    "root",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }
    }

    /**
     * Detect non-production Android builds.
     */
    private Signal checkBuildProvenance() {

        String tags = Build.TAGS == null
                ? ""
                : Build.TAGS.toLowerCase(Locale.US);

        String type = Build.TYPE == null
                ? ""
                : Build.TYPE.toLowerCase(Locale.US);

        boolean nonProduction =
                tags.contains("test-keys")
                        || "eng".equals(type)
                        || "userdebug".equals(type);

        return new Signal(
                "non_production_build",
                "root",
                nonProduction
                        ? State.DETECTED
                        : State.CLEAR,
                Strength.MEDIUM
        );
    }

    /**
     * Check current process memory mappings for
     * known instrumentation markers.
     */
    private Signal checkProcessMaps() {

        try (
                BufferedReader reader =
                        new BufferedReader(
                                new FileReader("/proc/self/maps")
                        )
        ) {

            String line;
            int count = 0;

            while (
                    (line = reader.readLine()) != null
                            && count++ < MAX_MAP_LINES
            ) {

                String value =
                        line.toLowerCase(Locale.US);

                if (containsInstrumentationMarker(value)) {

                    return new Signal(
                            "instrumentation_map",
                            "instrumentation",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }
            }

            return new Signal(
                    "instrumentation_map",
                    "instrumentation",
                    State.CLEAR,
                    Strength.HIGH
            );

        } catch (Exception ignored) {

            return new Signal(
                    "instrumentation_map",
                    "instrumentation",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }
    }

    /**
     * Check file descriptors for instrumentation references.
     */
    private Signal checkFileDescriptors() {

        File directory = new File("/proc/self/fd");

        File[] descriptors;

        try {

            descriptors = directory.listFiles();

        } catch (SecurityException ignored) {

            descriptors = null;
        }

        if (descriptors == null) {

            return new Signal(
                    "instrumentation_fd",
                    "instrumentation",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }

        int count = 0;

        for (File descriptor : descriptors) {

            if (count++ >= MAX_FDS) {
                break;
            }

            try {

                String path =
                        descriptor
                                .getCanonicalPath()
                                .toLowerCase(Locale.US);

                if (containsInstrumentationMarker(path)) {

                    return new Signal(
                            "instrumentation_fd",
                            "instrumentation",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }

            } catch (Exception ignored) {
                // Descriptor may disappear while enumerating.
            }
        }

        return new Signal(
                "instrumentation_fd",
                "instrumentation",
                State.CLEAR,
                Strength.HIGH
        );
    }

    /**
     * Detect suspicious instrumentation thread names.
     */
    private Signal checkThreadNames() {

        File directory =
                new File("/proc/self/task");

        File[] tasks;

        try {

            tasks = directory.listFiles();

        } catch (SecurityException ignored) {

            tasks = null;
        }

        if (tasks == null) {

            return new Signal(
                    "instrumentation_thread",
                    "instrumentation",
                    State.UNAVAILABLE,
                    Strength.HIGH
            );
        }

        boolean genericGlibThread = false;

        int count = 0;

        for (File task : tasks) {

            if (count++ >= MAX_TASKS) {
                break;
            }

            try (
                    BufferedReader reader =
                            new BufferedReader(
                                    new FileReader(
                                            new File(task, "comm")
                                    )
                            )
            ) {

                String name = reader.readLine();

                if (name == null) {
                    continue;
                }

                String value =
                        name.trim()
                                .toLowerCase(Locale.US);

                if (containsInstrumentationMarker(value)
                        || value.contains("pool-frida")
                        || value.contains("gmain-frida")) {

                    return new Signal(
                            "instrumentation_thread",
                            "instrumentation",
                            State.DETECTED,
                            Strength.HIGH
                    );
                }

                /*
                 * gmain/gdbus alone are not conclusive.
                 */
                if ("gmain".equals(value)
                        || "gdbus".equals(value)) {

                    genericGlibThread = true;
                }

            } catch (Exception ignored) {
                // Thread may disappear during enumeration.
            }
        }

        return new Signal(
                "instrumentation_thread",
                "instrumentation",
                genericGlibThread
                        ? State.DETECTED
                        : State.CLEAR,
                genericGlibThread
                        ? Strength.MEDIUM
                        : Strength.HIGH
        );
    }

    /**
     * Frida protocol detection.
     *
     * Known Frida ports:
     * 27042-27045
     *
     * Dynamically discovered ports are only treated as suspicious
     * if the Frida-compatible protocol responds.
     */
    private Signal checkFridaProtocol() {

        Set<Integer> ports =
                new LinkedHashSet<>();

        ports.add(27042);
        ports.add(27043);
        ports.add(27044);
        ports.add(27045);

        /*
         * Discover listening ports, but do NOT automatically
         * classify an arbitrary listening port as Frida.
         */
        addListeningPorts(
                "/proc/self/net/tcp",
                ports
        );

        addListeningPorts(
                "/proc/self/net/tcp6",
                ports
        );

        for (Integer port : ports) {

            if (port == null) {
                continue;
            }

            boolean knownFridaPort =
                    port >= 27042 && port <= 27045;

            try (
                    Socket socket =
                            new Socket()
            ) {

                socket.connect(
                        new InetSocketAddress(
                                "127.0.0.1",
                                port
                        ),
                        SOCKET_TIMEOUT_MS
                );

                socket.setSoTimeout(
                        SOCKET_TIMEOUT_MS
                );

                OutputStream output =
                        socket.getOutputStream();

                output.write(
                        new byte[]{0}
                );

                output.write(
                        "AUTH\r\n"
                                .getBytes(
                                        StandardCharsets.US_ASCII
                                )
                );

                output.flush();

                InputStream input =
                        socket.getInputStream();

                byte[] response =
                        new byte[96];

                int length =
                        input.read(response);

                if (length > 0) {

                    String banner =
                            new String(
                                    response,
                                    0,
                                    length,
                                    StandardCharsets.US_ASCII
                            ).toUpperCase(Locale.US);

                    if (banner.contains("REJECTED")
                            || banner.contains("OK")
                            || banner.contains("AGREE")) {

                        return new Signal(
                                "frida_protocol",
                                "instrumentation",
                                State.DETECTED,
                                knownFridaPort
                                        ? Strength.HIGH
                                        : Strength.MEDIUM
                        );
                    }
                }

            } catch (Exception ignored) {
                // Connection refused/timeout is not evidence.
            }
        }

        return new Signal(
                "frida_protocol",
                "instrumentation",
                State.CLEAR,
                Strength.MEDIUM
        );
    }

    /**
     * Discover listening TCP ports.
     */
    private void addListeningPorts(
            String path,
            Set<Integer> ports
    ) {

        try (
                BufferedReader reader =
                        new BufferedReader(
                                new FileReader(path)
                        )
        ) {

            String line;
            int count = 0;

            while (
                    (line = reader.readLine()) != null
                            && count++ < MAX_TCP_LINES
                            && ports.size() < MAX_PROTOCOL_PORTS
            ) {

                String[] columns =
                        line.trim().split("\\s+");

                if (columns.length < 4) {
                    continue;
                }

                /*
                 * TCP state 0A = LISTEN
                 */
                if (!"0A".equals(columns[3])) {
                    continue;
                }

                String[] address =
                        columns[1].split(":");

                if (address.length != 2) {
                    continue;
                }

                int port;

                try {

                    port =
                            Integer.parseInt(
                                    address[1],
                                    16
                            );

                } catch (NumberFormatException ignored) {

                    continue;
                }

                /*
                 * Only consider valid non-system ports.
                 */
                if (port > 1024 && port <= 65535) {

                    /*
                     * Keep the discovered port available for
                     * protocol verification.
                     */
                    ports.add(port);
                }
            }

        } catch (Exception ignored) {
            // Procfs visibility varies across Android versions.
        }
    }

    /**
     * Instrumentation markers.
     */
    private boolean containsInstrumentationMarker(
            String value
    ) {

        if (value == null) {
            return false;
        }

        return value.contains("frida")
                || value.contains("gum-js")
                || value.contains("linjector")
                || value.contains("/re.frida.")
                || value.contains("zygisk");
    }

    /**
     * Count detected signals by strength.
     */
    private int countDetected(
            List<Signal> signals,
            Strength strength
    ) {

        int count = 0;

        for (Signal signal : signals) {

            if (signal.state == State.DETECTED
                    && signal.strength == strength) {

                count++;
            }
        }

        return count;
    }

    /**
     * Determine whether critical checks were unavailable.
     */
    private boolean criticalChecksUnavailable(
            List<Signal> signals
    ) {

        boolean mapsUnavailable = false;
        boolean rootChecksUnavailable = true;

        for (Signal signal : signals) {

            if ("instrumentation_map".equals(signal.id)
                    && signal.state == State.UNAVAILABLE) {

                mapsUnavailable = true;
            }

            if ("root".equals(signal.category)
                    && signal.strength == Strength.HIGH
                    && signal.state != State.UNAVAILABLE) {

                rootChecksUnavailable = false;
            }
        }

        return mapsUnavailable
                || rootChecksUnavailable;
    }

    /**
     * Convert assessment to JSON.
     */
    private JSONObject toJson(
            Assessment assessment
    ) {

        JSONObject result =
                new JSONObject();

        JSONArray evidence =
                new JSONArray();

        JSONArray unavailable =
                new JSONArray();

        JSONArray unknownReasons =
                new JSONArray();

        try {

            for (String reason :
                    assessment.unknownReasons) {

                unknownReasons.put(reason);
            }

            for (Signal signal :
                    assessment.signals) {

                if (signal.state == State.DETECTED) {

                    evidence.put(signal.id);
                }

                if (signal.state == State.UNAVAILABLE) {

                    unavailable.put(signal.id);
                }
            }

            result.put(
                    "status",
                    assessment.status
            );

            result.put(
                    "statusName",
                    statusName(
                            assessment.status
                    )
            );

            result.put(
                    "platform",
                    "android"
            );

            result.put(
                    "osVersion",
                    Build.VERSION.RELEASE
            );

            result.put(
                    "apiLevel",
                    Build.VERSION.SDK_INT
            );

            result.put(
                    "evidence",
                    evidence
            );

            result.put(
                    "unavailableChecks",
                    unavailable
            );

            result.put(
                    "unknownReasons",
                    unknownReasons
            );

            result.put(
                    "localOnly",
                    true
            );

        } catch (JSONException ignored) {
            // JSON values above are valid.
        }

        return result;
    }

    private String statusName(int status) {

        if (status == COMPROMISED) {
            return "COMPROMISED";
        }

        if (status == UNKNOWN) {
            return "UNKNOWN";
        }

        return "SAFE";
    }
}
