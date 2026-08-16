// SPDX-License-Identifier: MIT
// cpp-inotify-watch — Linux filesystem event monitor using inotify(7)
// Build: g++ -std=c++23 -O2 -Wall -Wextra src/main.cpp -o inotify-watch
// Usage: ./inotify-watch [options] [path...]

#include <algorithm>
#include <atomic>
#include <charconv>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <poll.h>
#include <print>
#include <string>
#include <string_view>
#include <system_error>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>
#include <unordered_map>
#include <vector>

namespace fs = std::filesystem;
using std::string;
using std::string_view;

// ── Error / Result (std::expected, C++23) ──
struct Error {
  int code;
  string message;
};
template <typename T>
using Result = std::expected<T, Error>;

// ── Event types ──
enum class EventType {
  Access, Modify, Attrib, CloseWrite, CloseNoWrite, Open,
  MovedFrom, MovedTo, Create, Delete, DeleteSelf, MoveSelf,
  Unmount, QOverflow, Ignored,
};

static const char* type_name(EventType t) {
  switch (t) {
    case EventType::Access:      return "ACCESS";
    case EventType::Modify:      return "MODIFY";
    case EventType::Attrib:      return "ATTRIB";
    case EventType::CloseWrite:  return "CLOSE_WRITE";
    case EventType::CloseNoWrite:return "CLOSE_NOWRITE";
    case EventType::Open:        return "OPEN";
    case EventType::MovedFrom:   return "MOVED_FROM";
    case EventType::MovedTo:     return "MOVED_TO";
    case EventType::Create:      return "CREATE";
    case EventType::Delete:      return "DELETE";
    case EventType::DeleteSelf:  return "DELETE_SELF";
    case EventType::MoveSelf:    return "MOVE_SELF";
    case EventType::Unmount:     return "UNMOUNT";
    case EventType::QOverflow:   return "Q_OVERFLOW";
    case EventType::Ignored:     return "IGNORED";
  }
  return "?";
}

struct Event {
  EventType type = EventType::Ignored;
  string path;
  bool is_dir = false;
  uint32_t cookie = 0;
  int64_t ts = 0;
};

// ── Paleta ANSI MUTABLE (--no-color la vacía; si fuera constexpr el flag no haría nada) ──
static string C_CREATE = "\x1b[32m";
static string C_MODIFY = "\x1b[33m";
static string C_DELETE = "\x1b[31m";
static string C_MOVE   = "\x1b[36m";
static string C_ATTRIB = "\x1b[35m";
static string C_OPEN   = "\x1b[34m";
static string C_BOLD   = "\x1b[1m";
static string C_DIM    = "\x1b[2m";
static string C_RST    = "\x1b[0m";

// ── FileWatcher: RAII sobre inotify(7) ──
class FileWatcher {
public:
  FileWatcher() {
    fd_ = inotify_init1(IN_NONBLOCK);
    if (fd_ == -1)
      throw std::system_error(errno, std::generic_category(), "inotify_init1");
  }
  ~FileWatcher() {
    if (fd_ >= 0) ::close(fd_);
  }
  FileWatcher(const FileWatcher&) = delete;
  FileWatcher& operator=(const FileWatcher&) = delete;

  int fd() const { return fd_; }

  static uint32_t default_mask() {
    return IN_CREATE | IN_MODIFY | IN_DELETE | IN_MOVED_FROM | IN_MOVED_TO | IN_ATTRIB;
  }
  static uint32_t all_mask() { return IN_ALL_EVENTS; }

  Result<bool> add_watch(const string& path, uint32_t mask) {
    if (path_to_wd_.contains(path))
      return std::unexpected(Error{0, "already watching: " + path});
    int wd = inotify_add_watch(fd_, path.c_str(), mask);
    if (wd == -1)
      return std::unexpected(Error{errno, "inotify_add_watch(" + path + "): " + std::strerror(errno)});
    wd_to_path_[wd] = path;
    path_to_wd_[path] = wd;
    return true;
  }

  Result<bool> remove_watch(const string& path) {
    auto it = path_to_wd_.find(path);
    if (it == path_to_wd_.end())
      return std::unexpected(Error{0, "not watching: " + path});
    int wd = it->second;
    if (inotify_rm_watch(fd_, wd) == -1)
      return std::unexpected(Error{errno, "inotify_rm_watch(" + path + "): " + std::strerror(errno)});
    wd_to_path_.erase(wd);
    path_to_wd_.erase(it);
    return true;
  }

  // Lectura NO bloqueante de todos los eventos pendientes (drena la cola).
  Result<std::vector<Event>> drain() {
    std::vector<Event> out;
    char buf[65536];
    for (;;) {
      ssize_t n = ::read(fd_, buf, sizeof(buf));
      if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;  // cola drenada
        if (errno == EINTR) continue;
        return std::unexpected(Error{errno, "read(inotify): " + string(std::strerror(errno))});
      }
      if (n == 0) break;
      int64_t ts = now_secs();
      for (char* p = buf; p < buf + n; ) {
        auto* ev = reinterpret_cast<inotify_event*>(p);
        Event e;
        e.type = map_mask(ev->mask);
        e.is_dir = (ev->mask & IN_ISDIR) != 0;
        e.cookie = ev->cookie;
        string base = wd_path(ev->wd);
        if (ev->len > 0)
          e.path = base.empty() ? string(ev->name) : base + "/" + string(ev->name);
        else
          e.path = std::move(base);
        e.ts = ts;
        out.push_back(std::move(e));
        p += sizeof(inotify_event) + ev->len;
      }
    }
    return out;
  }

  // Loop con poll(): 500ms de timeout para responder a stop()/timeout.
  // Devuelve el total de eventos procesados, o -1 en error.
  int run(const std::function<void(const Event&)>& cb, int timeout_sec, std::atomic<bool>& stop) {
    struct pollfd pfd = { fd_, POLLIN, 0 };
    auto start = std::chrono::steady_clock::now();
    int total = 0;
    while (!stop.load()) {
      if (timeout_sec > 0) {
        auto el = std::chrono::duration_cast<std::chrono::seconds>(
                      std::chrono::steady_clock::now() - start).count();
        if (el >= timeout_sec) break;
      }
      int ret = ::poll(&pfd, 1, 500);
      if (ret == -1) {
        if (errno == EINTR) continue;
        return -1;
      }
      if (ret > 0 && (pfd.revents & POLLIN)) {
        auto r = drain();
        if (!r) return -1;
        for (const auto& e : *r) { cb(e); ++total; }
      }
    }
    return total;
  }

  size_t watch_count() const { return path_to_wd_.size(); }

private:
  static EventType map_mask(uint32_t mask) {
    if (mask & IN_MOVED_FROM)  return EventType::MovedFrom;
    if (mask & IN_MOVED_TO)    return EventType::MovedTo;
    if (mask & IN_CREATE)      return EventType::Create;
    if (mask & IN_DELETE)      return EventType::Delete;
    if (mask & IN_DELETE_SELF) return EventType::DeleteSelf;
    if (mask & IN_MOVE_SELF)   return EventType::MoveSelf;
    if (mask & IN_ATTRIB)      return EventType::Attrib;
    if (mask & IN_MODIFY)      return EventType::Modify;
    if (mask & IN_ACCESS)      return EventType::Access;
    if (mask & IN_CLOSE_WRITE) return EventType::CloseWrite;
    if (mask & IN_CLOSE_NOWRITE) return EventType::CloseNoWrite;
    if (mask & IN_OPEN)        return EventType::Open;
    if (mask & IN_UNMOUNT)     return EventType::Unmount;
    if (mask & IN_Q_OVERFLOW)  return EventType::QOverflow;
    return EventType::Ignored;
  }

  string wd_path(int wd) {
    auto it = wd_to_path_.find(wd);
    return it == wd_to_path_.end() ? string{} : it->second;
  }

  static int64_t now_secs() {
    return std::chrono::duration_cast<std::chrono::seconds>(
               std::chrono::system_clock::now().time_since_epoch()).count();
  }

  int fd_ = -1;
  std::map<int, string> wd_to_path_;
  std::map<string, int> path_to_wd_;
};

// ── Helpers de formato ──
static string timestamp(int64_t ts) {
  time_t t = static_cast<time_t>(ts);
  struct tm tmv{};
  localtime_r(&t, &tmv);
  char buf[16];
  std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tmv.tm_hour, tmv.tm_min, tmv.tm_sec);
  return buf;
}

static string json_escape(const string& s) {
  string out;
  out.reserve(s.size() + 8);
  for (char c : s) {
    if (c == '"' || c == '\\') { out += '\\'; out += c; }
    else if (c == '\n') out += "\\n";
    else out += c;
  }
  return out;
}

static string json_of(const Event& e) {
  return std::format("{{\"ts\":{},\"type\":\"{}\",\"path\":\"{}\",\"dir\":{},\"cookie\":{}}}",
                     e.ts, type_name(e.type), json_escape(e.path),
                     e.is_dir ? "true" : "false", e.cookie);
}

static string json_rename(const Event& from, const Event& to) {
  return std::format("{{\"ts\":{},\"type\":\"RENAME\",\"from\":\"{}\",\"to\":\"{}\",\"dir\":{},\"cookie\":{}}}",
                     to.ts, json_escape(from.path), json_escape(to.path),
                     to.is_dir ? "true" : "false", to.cookie);
}

static string type_color(EventType t) {
  switch (t) {
    case EventType::Create:  return C_CREATE;
    case EventType::Modify:  return C_MODIFY;
    case EventType::Delete:
    case EventType::DeleteSelf: return C_DELETE;
    case EventType::MovedFrom:
    case EventType::MovedTo: return C_MOVE;
    case EventType::Attrib:  return C_ATTRIB;
    case EventType::Open:
    case EventType::Access:
    case EventType::CloseWrite:
    case EventType::CloseNoWrite: return C_OPEN;
    default:                 return C_DIM;
  }
}

static void print_event(const Event& e, bool json) {
  if (json) {
    std::println(std::cout, "{}", json_of(e));
    return;
  }
  char tb[16];
  std::snprintf(tb, sizeof(tb), "%-10s ", type_name(e.type));
  string line = "[" + timestamp(e.ts) + "] " + type_color(e.type) + tb
              + (e.is_dir ? (C_BOLD + "dir " + C_RST) : "file ") + e.path;
  std::println(std::cout, "{}", line);
}

static void print_rename(const Event& from, const Event& to, bool json) {
  if (json) {
    std::println(std::cout, "{}", json_rename(from, to));
    return;
  }
  string line = "[" + timestamp(to.ts) + "] " + C_MOVE + "RENAME" + C_RST + "     "
              + (to.is_dir ? (C_BOLD + "dir " + C_RST) : "file ") + from.path + " -> " + to.path;
  std::println(std::cout, "{}", line);
}

static string fmt_duration(double secs) {
  char buf[24];
  if (secs < 60.0) std::snprintf(buf, sizeof(buf), "%.1fs", secs);
  else std::snprintf(buf, sizeof(buf), "%dm%02ds", static_cast<int>(secs) / 60,
                     static_cast<int>(secs) % 60);
  return buf;
}

// ── Estado del watcher ──
struct WatchState {
  std::unordered_map<uint32_t, Event> pending;   // cookies MOVED_FROM sin pareja
  std::map<string, uint64_t> counts;
};

static void process_one(const Event& e, bool json, WatchState& st) {
  if (e.type == EventType::MovedFrom && e.cookie != 0) {
    st.pending[e.cookie] = e;   // esperar al MOVED_TO con el mismo cookie
    return;
  }
  if (e.type == EventType::MovedTo && e.cookie != 0) {
    auto it = st.pending.find(e.cookie);
    if (it != st.pending.end()) {
      print_rename(it->second, e, json);
      st.counts["RENAME"]++;
      st.pending.erase(it);
      return;
    }
  }
  print_event(e, json);
  st.counts[type_name(e.type)]++;
}

static void flush_pending(WatchState& st, bool json) {
  for (auto& [cookie, ev] : st.pending) {
    print_event(ev, json);
    st.counts[type_name(ev.type)]++;
  }
  st.pending.clear();
}

static void print_summary(const WatchState& st, int total, size_t npaths, double elapsed, bool json) {
  if (json) return;
  string parts;
  for (const auto& [name, cnt] : st.counts)
    parts += name + " " + std::to_string(cnt) + "  ";
  string line = C_BOLD + "SUMMARY" + C_RST + "  watched " + std::to_string(npaths)
              + " path(s) · " + std::to_string(total) + " events in " + fmt_duration(elapsed)
              + " · " + parts;
  std::println(std::cout, "{}", line);
}

// ── Máscaras por nombre ──
static uint32_t mask_bit(string_view name) {
  if (name == "create") return IN_CREATE;
  if (name == "modify") return IN_MODIFY;
  if (name == "delete") return IN_DELETE;
  if (name == "move")   return IN_MOVED_FROM | IN_MOVED_TO;
  if (name == "attrib") return IN_ATTRIB;
  if (name == "open")   return IN_OPEN;
  if (name == "close")  return IN_CLOSE_WRITE | IN_CLOSE_NOWRITE;
  if (name == "access") return IN_ACCESS;
  return 0;
}

static Result<uint32_t> parse_mask(const char* s) {
  string_view sv{s};
  uint32_t m = 0;
  bool any = false;
  size_t start = 0;
  while (start <= sv.size()) {
    size_t comma = sv.find(',', start);
    string_view name = sv.substr(start, comma == string_view::npos ? sv.size() - start : comma - start);
    while (!name.empty() && name.front() == ' ') name.remove_prefix(1);
    while (!name.empty() && name.back() == ' ') name.remove_suffix(1);
    if (!name.empty()) {
      any = true;
      if (name == "all") { m |= FileWatcher::all_mask(); }
      else {
        uint32_t bit = mask_bit(name);
        if (bit == 0) return std::unexpected(Error{0, "unknown mask name: " + string(name)});
        m |= bit;
      }
    }
    if (comma == string_view::npos) break;
    start = comma + 1;
  }
  if (!any) return std::unexpected(Error{0, "empty mask list"});
  return m;
}

static string mask_names(uint32_t m) {
  std::vector<string> names;
  if (m & IN_CREATE) names.push_back("CREATE");
  if (m & IN_MODIFY) names.push_back("MODIFY");
  if (m & IN_DELETE) names.push_back("DELETE");
  if (m & IN_MOVED_FROM || m & IN_MOVED_TO) names.push_back("MOVE");
  if (m & IN_ATTRIB) names.push_back("ATTRIB");
  if (m & IN_OPEN) names.push_back("OPEN");
  if (m & IN_CLOSE_WRITE || m & IN_CLOSE_NOWRITE) names.push_back("CLOSE");
  if (m & IN_ACCESS) names.push_back("ACCESS");
  string out;
  for (size_t i = 0; i < names.size(); ++i)
    out += (i ? "|" : "") + names[i];
  return out.empty() ? "NONE" : out;
}

// ── Watch recursivo (inotify NO es recursivo: hay que añadir cada dir explícitamente) ──
static Result<int> add_recursive(FileWatcher& fw, const string& root, uint32_t mask) {
  int added = 0;
  auto r = fw.add_watch(root, mask);
  if (!r) return std::unexpected(r.error());
  ++added;
  std::error_code ec;
  fs::recursive_directory_iterator it(root, fs::directory_options::skip_permission_denied, ec), end;
  for (; it != end; it.increment(ec)) {
    if (ec) { ec.clear(); continue; }   // dir sin permisos/zombie: saltar, no abortar el scan
    if (it->is_directory(ec)) {
      if (ec) { ec.clear(); continue; }
      auto r2 = fw.add_watch(it->path().string(), mask);
      if (r2) ++added;
    }
  }
  return added;
}

// ── Modo watch en vivo ──
static int watch(const std::vector<string>& paths, bool recursive, bool json,
                 uint32_t mask, int timeout) {
  FileWatcher fw;
  size_t npaths = 0;
  for (const auto& p : paths) {
    std::error_code ec;
    if (recursive && fs::is_directory(p, ec)) {
      auto r = add_recursive(fw, p, mask);
      if (!r) { std::cerr << "error: " << r.error().message << "\n"; return 1; }
      ++npaths;
      if (!json)
        std::println(std::cout, "{}  watching {} (recursive, {} dirs)", C_DIM + "•" + C_RST, p, *r);
    } else {
      auto r = fw.add_watch(p, mask);
      if (!r) { std::cerr << "error: " << r.error().message << "\n"; return 1; }
      ++npaths;
      if (!json)
        std::println(std::cout, "{}  watching {}", C_DIM + "•" + C_RST, p);
    }
  }

  if (!json) {
    std::println(std::cout, "{}", C_BOLD + "INOTIFY WATCH — filesystem events (inotify(7))" + C_RST);
    std::println(std::cout, "{}", C_DIM + "mask: " + mask_names(mask) + " · Ctrl+C para salir" + C_RST);
  }

  WatchState st;
  std::atomic<bool> stop{false};
  auto start = std::chrono::steady_clock::now();
  int total = fw.run([&](const Event& e) { process_one(e, json, st); }, timeout, stop);
  if (total < 0) { std::cerr << "error: watch loop failed\n"; return 1; }
  flush_pending(st, json);
  double elapsed = std::chrono::duration<double>(
                       std::chrono::steady_clock::now() - start).count();
  print_summary(st, total, npaths, elapsed, json);
  return 0;
}

// ── Modo demo: flujo sintético realista (contenedores/VMs, screenshots) ──
static int run_demo(bool json) {
  struct DemoEv { EventType type; const char* path; bool dir; };
  static const DemoEv kDemo[] = {
    {EventType::Create,    "/home/dev/app/src/components/Button.tsx", false},
    {EventType::Modify,    "/home/dev/app/src/components/Button.tsx", false},
    {EventType::Modify,    "/home/dev/app/src/components/Button.tsx", false},
    {EventType::Attrib,    "/home/dev/app/src/components/Button.tsx", false},
    {EventType::MovedFrom, "/home/dev/app/src/components/Button.tsx", false},
    {EventType::MovedTo,   "/home/dev/app/src/components/Button.tsx.bak", false},
    {EventType::Create,    "/home/dev/app/src/components/Button.tsx", false},
    {EventType::Modify,    "/home/dev/app/src/components/Button.tsx", false},
    {EventType::Create,    "/home/dev/app/dist/main.js", false},
    {EventType::Modify,    "/home/dev/app/dist/main.js", false},
    {EventType::Create,    "/home/dev/app/dist/assets", true},
    {EventType::Create,    "/home/dev/app/dist/assets/app-1a2b3c.css", false},
    {EventType::Create,    "/home/dev/app/dist/assets/app-4d5e6f.js", false},
    {EventType::Modify,    "/home/dev/app/dist/index.html", false},
    {EventType::Delete,    "/home/dev/app/src/components/Button.tsx.bak", false},
    {EventType::Delete,    "/home/dev/app/tmp/cache-0.tmp", false},
    {EventType::Create,    "/home/dev/app/dist/assets/app-7a8b9c.js", false},
    {EventType::Modify,    "/home/dev/app/dist/assets/app-7a8b9c.js", false},
  };
  const size_t n = sizeof(kDemo) / sizeof(kDemo[0]);
  int64_t base = std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::system_clock::now().time_since_epoch()).count() - static_cast<int64_t>(n);

  if (!json) {
    std::println(std::cout, "{}", C_BOLD + "INOTIFY WATCH — demo (flujo sintético)" + C_RST);
    std::println(std::cout, "{}", C_DIM + "mask: CREATE|MODIFY|DELETE|MOVE|ATTRIB · /home/dev/app" + C_RST);
  }

  WatchState st;
  for (size_t i = 0; i < n; ++i) {
    Event e;
    e.type = kDemo[i].type;
    e.path = kDemo[i].path;
    e.is_dir = kDemo[i].dir;
    e.cookie = (kDemo[i].type == EventType::MovedFrom || kDemo[i].type == EventType::MovedTo)
                   ? 4242 : 0;
    e.ts = base + static_cast<int64_t>(i);
    process_one(e, json, st);
  }
  flush_pending(st, json);
  print_summary(st, static_cast<int>(n), 1, static_cast<double>(n), json);
  return 0;
}

// ── Selftest ──
static int g_pass = 0;
static int g_fail = 0;

static void check(bool ok, const string& name) {
  if (ok) {
    ++g_pass;
    std::println(std::cout, "{}", C_CREATE + "PASS" + C_RST + "  " + name);
  } else {
    ++g_fail;
    std::println(std::cout, "{}", C_DELETE + "FAIL" + C_RST + "  " + name);
  }
}

static bool has_type(const std::vector<Event>& evs, EventType t) {
  return std::any_of(evs.begin(), evs.end(),
                     [t](const Event& e) { return e.type == t; });
}

static int selftest() {
  std::println(std::cout, "{}", C_BOLD + "inotify-watch selftest" + C_RST);

  // 1-2. init
  try {
    FileWatcher fw0;
    check(true, "RAII: inotify_init1 sin excepción");
  } catch (const std::system_error&) {
    check(false, "RAII: inotify_init1 sin excepción");
  }
  FileWatcher fw;
  check(fw.fd() >= 0, "fd del watcher válido");

  // 3. dir temporal
  char tmpl[] = "/tmp/inotify-watch-test-XXXXXX";
  char* d = mkdtemp(tmpl);
  check(d != nullptr, "mkdtemp crea dir de test");
  if (!d) {
    std::println(std::cout, "{}", C_DELETE + "FAIL" + C_RST + "  no se puede continuar sin dir temporal");
    return 1;
  }
  string dir = d;
  const uint32_t mask = FileWatcher::default_mask();

  // 4-6. add_watch
  auto r = fw.add_watch(dir, mask);
  check(r.has_value() && *r, "add_watch sobre directorio");
  auto r2 = fw.add_watch(dir, mask);
  check(!r2.has_value(), "add_watch duplicado rechazado");
  auto r3 = fw.add_watch(dir + "/nope", mask);
  check(!r3.has_value(), "add_watch sobre ruta inexistente rechazado");

  // 7-14. eventos básicos
  string a = dir + "/a.txt";
  string b = dir + "/b.txt";
  {
    std::ofstream os(a);
    os << "hello";
  }                                   // CREATE + MODIFY (+ CLOSE_WRITE no está en la máscara)
  ::chmod(a.c_str(), 0600);           // ATTRIB
  ::rename(a.c_str(), b.c_str());     // MOVED_FROM + MOVED_TO (mismo cookie)
  ::remove(b.c_str());                // DELETE
  auto evs = fw.drain();
  check(evs.has_value(), "drain devuelve Result");
  if (evs) {
    check(evs->size() >= 5, "5+ eventos capturados (create/modify/attrib/move/delete)");
    check(has_type(*evs, EventType::Create), "CREATE detectado");
    check(has_type(*evs, EventType::Modify), "MODIFY detectado");
    check(has_type(*evs, EventType::Attrib), "ATTRIB detectado");
    check(has_type(*evs, EventType::MovedFrom), "MOVED_FROM detectado");
    check(has_type(*evs, EventType::MovedTo), "MOVED_TO detectado");
    check(has_type(*evs, EventType::Delete), "DELETE detectado");
    auto mf = std::find_if(evs->begin(), evs->end(),
                           [](const Event& e) { return e.type == EventType::MovedFrom; });
    auto mt = std::find_if(evs->begin(), evs->end(),
                           [](const Event& e) { return e.type == EventType::MovedTo; });
    bool paired = mf != evs->end() && mt != evs->end() &&
                  mf->cookie != 0 && mf->cookie == mt->cookie &&
                  mf->path == a && mt->path == b;
    check(paired, "pairing por cookie: a.txt -> b.txt");
    auto cr = std::find_if(evs->begin(), evs->end(),
                           [&](const Event& e) { return e.type == EventType::Create && e.path == a; });
    check(cr != evs->end(), "resolución wd->path (a.txt)");
  }

  // 15. IN_ISDIR
  string sub = dir + "/sub";
  ::mkdir(sub.c_str(), 0755);
  auto evs2 = fw.drain();
  check(evs2 && has_type(*evs2, EventType::Create) &&
        std::any_of(evs2->begin(), evs2->end(),
                    [&](const Event& e) { return e.type == EventType::Create && e.is_dir && e.path == sub; }),
        "flag IN_ISDIR en creación de directorio");

  // 16. filtro de máscara
  {
    FileWatcher fw2;
    fw2.add_watch(dir, IN_CREATE);
    string c = dir + "/c.txt";
    {
      std::ofstream os(c);
      os << "x";
    }  // CREATE + MODIFY
    auto evs3 = fw2.drain();
    check(evs3 && has_type(*evs3, EventType::Create) && !has_type(*evs3, EventType::Modify),
          "filtro de máscara: solo CREATE, MODIFY excluido");
  }
  // inotify entrega el evento a TODOS los wd que vigilan la ruta: fw también
  // recibió CREATE(c.txt) — drenar su cola para no contaminar el test siguiente.
  auto clear_fw = fw.drain();
  (void)clear_fw;

  // 17-19. remove_watch
  auto rr = fw.remove_watch(dir);
  check(rr.has_value() && *rr, "remove_watch");
  string efile = dir + "/e.txt";
  {
    std::ofstream os(efile);
    os << "y";
  }
  auto evs4 = fw.drain();
  check(evs4 && !has_type(*evs4, EventType::Create), "sin eventos tras remove_watch");
  auto rr2 = fw.remove_watch(dir);
  check(!rr2.has_value(), "remove_watch de ruta no vigilada rechazado");

  // 20-21. watch de archivo directo
  string ff = dir + "/ff.txt";
  {
    std::ofstream os(ff);
    os << "z";
  }
  {
    FileWatcher fwf;
    auto rf = fwf.add_watch(ff, IN_MODIFY);
    check(rf.has_value() && *rf, "add_watch sobre archivo regular");
    {
      std::ofstream os(ff, std::ios::app);
      os << "more";
    }
    auto evs5 = fwf.drain();
    check(evs5 && std::any_of(evs5->begin(), evs5->end(),
                              [&](const Event& e) { return e.type == EventType::Modify && e.path == ff; }),
          "watch de archivo: MODIFY detectado");
  }

  // 22-23. watch recursivo
  {
    FileWatcher fwr;
    auto rw = add_recursive(fwr, dir, mask);
    check(rw.has_value() && *rw >= 2, "add_recursive escanea subdirectorios");
    string deep = dir + "/sub/deep.txt";
    {
      std::ofstream os(deep);
      os << "deep";
    }
    auto evs6 = fwr.drain();
    check(evs6 && std::any_of(evs6->begin(), evs6->end(),
                              [&](const Event& e) { return e.type == EventType::Create && e.path == deep; }),
          "watch recursivo: evento en subdirectorio anidado");
  }

  // 24-26. JSON
  {
    Event je{EventType::Create, "/tmp/x/a b.txt", false, 0, 1755220138};
    string js = json_of(je);
    check(js.find("\"type\":\"CREATE\"") != string::npos, "JSON: claves con comillas (type)");
    check(js.find("\"path\":\"/tmp/x/a b.txt\"") != string::npos, "JSON: path con espacios");
    Event je2{EventType::Create, "/tmp/x/a\"b.txt", false, 0, 1755220138};
    string js2 = json_of(je2);
    check(js2.find("a\\\"b.txt") != string::npos, "JSON: escape de comillas");
  }

  // 27. drain idle
  auto evs7 = fw.drain();
  check(evs7 && evs7->empty(), "drain sin eventos pendientes devuelve vacío");

  // 28. cleanup
  fs::remove_all(dir);
  check(!fs::exists(dir), "cleanup elimina el dir de test");

  std::println(std::cout, "{}", C_BOLD + std::to_string(g_pass) + " passed, "
                                     + std::to_string(g_fail) + " failed" + C_RST);
  return g_fail == 0 ? 0 : 1;
}

// ── Help ──
static void print_help() {
  std::println(std::cout, "{}", C_BOLD + "inotify-watch — monitor de eventos del sistema de archivos (inotify(7))" + C_RST);
  std::println(std::cout, "{}", "C++23 sin dependencias externas — Linux");
  std::println(std::cout, "{}", "");
  std::println(std::cout, "{}", "Uso: ./inotify-watch [opciones] [ruta...]    (ruta por defecto: .)");
  std::println(std::cout, "{}", "");
  std::println(std::cout, "{}", "Opciones:");
  std::println(std::cout, "{}", "  -r, --recursive     vigila subdirectorios recursivamente");
  std::println(std::cout, "{}", "  -m, --mask LISTA    eventos: create,modify,delete,move,attrib,open,close,access,all");
  std::println(std::cout, "{}", "                      (por defecto: create,modify,delete,move,attrib)");
  std::println(std::cout, "{}", "  -j, --json          salida JSON por línea para scripting");
  std::println(std::cout, "{}", "  -t, --timeout N     salir tras N segundos (0 = hasta Ctrl+C)");
  std::println(std::cout, "{}", "      --demo          imprime un flujo sintético de eventos y sale");
  std::println(std::cout, "{}", "      --selftest      ejecuta los tests de auto-verificación y sale");
  std::println(std::cout, "{}", "      --no-color      sin códigos ANSI (pipes/logs)");
  std::println(std::cout, "{}", "  -h, --help          esta ayuda");
  std::println(std::cout, "{}", "");
  std::println(std::cout, "{}", "Ejemplos:");
  std::println(std::cout, "{}", "  ./inotify-watch                       # vigila . con la máscara por defecto");
  std::println(std::cout, "{}", "  ./inotify-watch -r src docs           # vigila dos árboles recursivamente");
  std::println(std::cout, "{}", "  ./inotify-watch --mask create,delete /tmp");
  std::println(std::cout, "{}", "  ./inotify-watch --json -t 10 /var/log # 10s de eventos como JSONL");
}

// ── Main ──
int main(int argc, char** argv) {
  std::vector<string> paths;
  bool recursive = false;
  bool json = false;
  bool demo = false;
  bool selftest_mode = false;
  bool no_color = false;
  int timeout = 0;
  uint32_t mask = FileWatcher::default_mask();

  for (int i = 1; i < argc; ++i) {
    string_view a{argv[i]};
    if (a == "-h" || a == "--help") {
      print_help();
      return 0;
    } else if (a == "-r" || a == "--recursive") {
      recursive = true;
    } else if (a == "-j" || a == "--json") {
      json = true;
    } else if (a == "--demo") {
      demo = true;
    } else if (a == "--selftest") {
      selftest_mode = true;
    } else if (a == "--no-color") {
      no_color = true;
    } else if (a == "-t" || a == "--timeout") {
      if (i + 1 >= argc) { std::cerr << "--timeout requiere un número\n"; return 2; }
      ++i;
      auto [ptr, ec] = std::from_chars(argv[i], argv[i] + std::strlen(argv[i]), timeout);
      if (ec != std::errc()) { std::cerr << "timeout inválido: " << argv[i] << "\n"; return 2; }
    } else if (a == "-m" || a == "--mask") {
      if (i + 1 >= argc) { std::cerr << "--mask requiere una lista\n"; return 2; }
      auto m = parse_mask(argv[++i]);
      if (!m) { std::cerr << "error: " << m.error().message << "\n"; return 2; }
      mask = *m;
    } else if (!a.empty() && a[0] == '-') {
      std::cerr << "opción desconocida: " << a << "\n";
      return 2;
    } else {
      paths.push_back(string(a));
    }
  }

  if (no_color) {
    C_CREATE = C_MODIFY = C_DELETE = C_MOVE = C_ATTRIB = C_OPEN = C_BOLD = C_DIM = C_RST = "";
  }
  if (selftest_mode) return selftest() == 0 ? 0 : 1;
  if (demo) return run_demo(json);
  if (paths.empty()) paths.push_back(".");
  return watch(paths, recursive, json, mask, timeout);
}
