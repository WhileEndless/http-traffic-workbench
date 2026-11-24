package trafficworkbench;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.PersistedObject;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

final class Persistence {
    private static final String PROFILE_KEY = "capture.profile.v1";
    private static final String ARCHIVE_KEY = "capture.archive.v1";
    private static final String HEADER = "# HTTP Traffic Workbench archive v2";
    private static final String LEGACY_SOURCED_HEADER = "# Burp Advanced Search archive v2";
    private static final String FIRST_HEADER = "# Burp Advanced Search archive v1";
    private static final String PREVIOUS_HEADER = "# Traffic Workbench archive v1";
    private static final long MAX_ARCHIVE_FILE = 64L * 1024 * 1024;
    private static final long MAX_PROFILE_FILE = 64 * 1024;

    private final MontoyaApi api;
    private final PersistedObject project;
    private volatile boolean persistArchive;

    Persistence(MontoyaApi api) {
        this.api = api;
        project = api.persistence().extensionData();
    }

    synchronized CaptureProfile loadProfile() {
        try {
            CaptureProfile profile = CaptureProfile.decode(project.getString(PROFILE_KEY));
            persistArchive = profile.persistArchive();
            return profile;
        } catch (IOException | RuntimeException ex) {
            api.logging().logToError("Could not load the project profile. Using default settings.");
            return CaptureProfile.defaults();
        }
    }

    synchronized void saveProfile(CaptureProfile profile) throws IOException {
        try {
            project.setString(PROFILE_KEY, profile.encode());
            persistArchive = profile.persistArchive();
            if (!persistArchive && project.getByteArray(ARCHIVE_KEY) != null) {
                project.deleteByteArray(ARCHIVE_KEY);
            }
        } catch (RuntimeException ex) {
            throw new IOException("Could not save the Burp project settings.", ex);
        }
    }

    boolean archiveEnabled() {
        return persistArchive;
    }

    synchronized boolean saveArchive(List<CapturedEntry> entries) {
        if (!persistArchive) {
            return true;
        }
        try {
            if (entries.isEmpty()) {
                project.deleteByteArray(ARCHIVE_KEY);
            } else {
                project.setByteArray(ARCHIVE_KEY, ByteArray.byteArray(encode(entries).getBytes(StandardCharsets.UTF_8)));
            }
            return true;
        } catch (RuntimeException ex) {
            api.logging().logToError("Could not save the traffic archive to the Burp project.");
            return false;
        }
    }

    synchronized List<CapturedEntry> loadArchive() {
        try {
            ByteArray bytes = project.getByteArray(ARCHIVE_KEY);
            return bytes == null ? List.of() : decode(new String(bytes.getBytes(), StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException ex) {
            api.logging().logToError("Could not read the traffic archive from the Burp project. " + ex.getMessage());
            return List.of();
        }
    }

    static void exportArchive(Path path, List<CapturedEntry> entries) throws IOException {
        write(path, encode(entries));
    }

    static List<CapturedEntry> importArchive(Path path) throws IOException {
        String text = read(path, MAX_ARCHIVE_FILE);
        return path.getFileName().toString().toLowerCase(java.util.Locale.ROOT).endsWith(".csv")
                ? LoggerCsv.read(text) : decode(text);
    }

    static void exportProfile(Path path, CaptureProfile profile) throws IOException {
        write(path, profile.encode());
    }

    static CaptureProfile importProfile(Path path) throws IOException {
        return CaptureProfile.decode(read(path, MAX_PROFILE_FILE));
    }

    private static void write(Path path, String value) throws IOException {
        Path target = path.toAbsolutePath();
        Path temp = Files.createTempFile(target.getParent(), ".http-traffic-workbench-", ".tmp");
        try {
            Files.writeString(temp, value, StandardCharsets.UTF_8);
            try {
                Files.move(temp, target, java.nio.file.StandardCopyOption.ATOMIC_MOVE,
                        java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            } catch (java.nio.file.AtomicMoveNotSupportedException ignored) {
                Files.move(temp, target, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(temp);
        }
    }

    private static String read(Path path, long maxBytes) throws IOException {
        if (Files.size(path) > maxBytes) {
            throw new IOException("The file exceeds the size limit.");
        }
        return Files.readString(path, StandardCharsets.UTF_8);
    }

    private static String encode(List<CapturedEntry> entries) {
        StringBuilder output = new StringBuilder(HEADER).append('\n');
        Base64.Encoder base64 = Base64.getEncoder();
        for (CapturedEntry entry : entries) {
            var exchange = entry.requestResponse();
            var service = exchange.request().httpService();
            output.append(base64.encodeToString(entry.userCode().getBytes(StandardCharsets.UTF_8))).append('\t')
                    .append(service.host()).append('\t').append(service.port()).append('\t')
                    .append(service.secure()).append('\t').append(entry.time()).append('\t')
                    .append(base64.encodeToString(exchange.request().toByteArray().getBytes())).append('\t')
                    .append(exchange.response() == null ? ""
                            : base64.encodeToString(exchange.response().toByteArray().getBytes()))
                    .append('\t').append(entry.source().name()).append('\t')
                    .append(entry.listenerPort()).append('\t').append(entry.annotated()).append('\n');
        }
        return output.toString();
    }

    private static List<CapturedEntry> decode(String text) throws IOException {
        List<CapturedEntry> result = new ArrayList<>();
        var lines = text.lines().iterator();
        String firstLine = text.lines().findFirst().orElse("");
        boolean sourced = firstLine.equals(HEADER) || firstLine.equals(LEGACY_SOURCED_HEADER);
        boolean portable = sourced || firstLine.equals(FIRST_HEADER) || firstLine.equals(PREVIOUS_HEADER);
        if (portable) lines.next();
        int lineNo = portable ? 1 : 0;
        Base64.Decoder base64 = Base64.getDecoder();
        while (lines.hasNext()) {
            String line = lines.next();
            lineNo++;
            if (line.isBlank()) {
                continue;
            }
            try {
                String[] fields = line.split("\t", -1);
                if (fields.length != (sourced ? 10 : portable ? 7 : 10) || fields[1].isBlank()
                        || (!fields[3].equals("true") && !fields[3].equals("false"))) {
                    throw new IllegalArgumentException("Unexpected columns");
                }
                int port = Integer.parseInt(fields[2]);
                if (port < 1 || port > 65535) {
                    throw new IllegalArgumentException("Invalid port");
                }
                var service = HttpService.httpService(fields[1], port, Boolean.parseBoolean(fields[3]));
                String label = portable ? new String(base64.decode(fields[0]), StandardCharsets.UTF_8) : fields[0];
                long time = Long.parseLong(fields[portable ? 4 : 7]);
                var request = HttpRequest.httpRequest(service, ByteArray.byteArray(base64.decode(fields[portable ? 5 : 8])));
                String response = fields[portable ? 6 : 9];
                var message = response.isEmpty() ? null : HttpResponse.httpResponse(ByteArray.byteArray(base64.decode(response)));
                var source = sourced ? TrafficSource.valueOf(fields[7]) : TrafficSource.ARCHIVE;
                int listener = sourced ? Integer.parseInt(fields[8]) : 0;
                boolean annotated = sourced && Boolean.parseBoolean(fields[9]);
                result.add(CapturedEntry.of(label, HttpRequestResponse.httpRequestResponse(request, message),
                        time, source, listener, annotated));
            } catch (RuntimeException ex) {
                throw new IOException("Could not read archive line " + lineNo + ".", ex);
            }
        }
        return result;
    }
}
