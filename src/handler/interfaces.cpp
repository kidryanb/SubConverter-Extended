#include <algorithm>
#include <chrono>
#include <cctype>
#include <condition_variable>
#include <cstdint>
#include <ctime>
#include <exception>
#include <iostream>
#include <memory>
#include <map>
#include <mutex>
#include <numeric>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <inja.hpp>
#include <rapidjson/stringbuffer.h>
#include <rapidjson/writer.h>
#include <yaml-cpp/yaml.h>

#include "config/binding.h"
#include "config/custom_openclash_rules.h"
#include "generator/config/nodemanip.h"
#include "generator/config/ruleconvert.h"
#include "generator/config/subexport.h"
#include "generator/template/templates.h"
#include "conversion_service.h"
#include "conversion_pipeline.h"
#include "interfaces.h"
#include "multithread.h"
#include "parser/mihomo_scheme_utils.h"
#include "parser/mihomo_bridge.h"
#include "script/cron.h"
#include "script/script_quickjs.h"
#include "runtime/owner_admission.h"
#include "runtime/runtime_coordinator.h"
#include "server/request_context.h"
#include "server/webserver.h"
#include "settings.h"
#include "statistics.h"
#include "upload.h"
#include "utils/time_compat.h"

const std::vector<std::string> DEFAULT_REMOTE_CONFIG_FALLBACKS = {
    "https://gcore.jsdelivr.net/gh/Aethersailor/Custom_OpenClash_Rules@refs/"
    "heads/main/cfg/Custom_Clash.ini",
    "https://testingcf.jsdelivr.net/gh/Aethersailor/"
    "Custom_OpenClash_Rules@refs/heads/main/cfg/Custom_Clash.ini",
    "https://cdn.jsdelivr.net/gh/Aethersailor/Custom_OpenClash_Rules@refs/"
    "heads/main/cfg/Custom_Clash.ini",
    "https://raw.githubusercontent.com/Aethersailor/Custom_OpenClash_Rules/"
    "main/cfg/Custom_Clash.ini"};

static void appendUniqueConfig(std::vector<std::string> &configs,
                               std::unordered_set<std::string> &seen,
                               const std::string &config) {
  if (!config.empty() && seen.insert(config).second)
    configs.emplace_back(config);
}

static void appendBundledConfig(
    std::vector<std::string> &configs,
    std::unordered_set<std::string> &seen,
    const custom_openclash_rules::Resource &resource) {
  if (!resource.matched())
    return;
  for (const std::string &path :
       custom_openclash_rules::localPathCandidates(resource))
    appendUniqueConfig(configs, seen, path);
}

static std::vector<std::string>
buildExternalConfigFallbacks(const std::string &failedConfig,
                             bool enhancedFallback,
                             bool legacyRemoteFallback) {
  std::vector<std::string> configs;
  std::unordered_set<std::string> seen;
  seen.insert(failedConfig);

  if (enhancedFallback) {
    custom_openclash_rules::Resource same_name =
        custom_openclash_rules::matchRepositoryUrl(failedConfig);
    if (same_name.kind ==
        custom_openclash_rules::ResourceKind::ConfigIni)
      appendBundledConfig(configs, seen, same_name);
  }

  if (enhancedFallback || legacyRemoteFallback) {
    for (const std::string &remote : DEFAULT_REMOTE_CONFIG_FALLBACKS)
      appendUniqueConfig(configs, seen, remote);
  }

  if (enhancedFallback) {
    appendBundledConfig(
        configs, seen,
        custom_openclash_rules::matchPublishedPath(
            "/Custom_OpenClash_Rules/main/cfg/Custom_Clash.ini"));
  }
  return configs;
}

static string_icase_map buildSubscriptionRequestHeaders() {
  string_icase_map headers;
  headers.emplace("User-Agent", "clash.meta");
  return headers;
}

#include "utils/base64/base64.h"
#include "utils/bounded_output.h"
#include "utils/bounded_executor.h"
#include "utils/cooperative_cpu.h"
#include "utils/file_extra.h"
#include "utils/ini_reader/ini_reader.h"
#include "utils/logger.h"
#include "utils/md5/md5_interface.h"
#include "utils/network.h"
#include "utils/redact.h"
#include "utils/resource_control.h"
#include "utils/regexp.h"
#include "utils/stl_extra.h"
#include "utils/string.h"
#include "utils/string_hash.h"
#include "utils/system.h"
#include "utils/urlencode.h"
#include "utils/yamlcpp_extra.h"
#include "webget.h"

extern WebServer webServer;

string_array gRegexBlacklist = {"(.*)*"};

static constexpr size_t kProviderUserAgentMaxLen = 512;

static std::string trimProviderUserAgentCandidate(const std::string &ua) {
  size_t begin = ua.find_first_not_of(" \t");
  if (begin == std::string::npos)
    return "";
  size_t end = ua.find_last_not_of(" \t");
  return ua.substr(begin, end - begin + 1);
}

static bool hasInvalidProviderUserAgentChar(const std::string &ua) {
  for (unsigned char ch : ua) {
    if (ch < 0x20 || ch == 0x7f)
      return true;
  }
  return false;
}

static bool containsAnyUserAgentToken(const std::string &lower_ua,
                                      const string_array &tokens) {
  for (const std::string &token : tokens) {
    if (lower_ua.find(token) != std::string::npos)
      return true;
  }
  return false;
}

static bool isExcludedProviderUserAgent(const std::string &ua) {
  std::string lower = toLower(ua);
  static const string_array browser_tokens = {
      "mozilla/",        "applewebkit/",     "chrome/",
      "chromium/",       "crios/",           "safari/",
      "firefox/",        "fxios/",           "edg/",
      "edga/",           "edgios/",          "edge/",
      "opr/",            "opera/",           "brave/",
      "vivaldi/",        "yabrowser/",       "samsungbrowser/",
      "ucbrowser/",      "maxthon/",         "qqbrowser/",
      "mqqbrowser/",     "sogou/",           "360se",
      "360ee",           "whale/",           "micromessenger/",
      "msie ",           "trident/"};
  static const string_array inspection_tool_tokens = {
      "curl/",             "wget/",         "python-requests/",
      "python-urllib/",    "postmanruntime/", "insomnia/",
      "go-http-client/",   "java/",         "apache-httpclient/",
      "httpie/",           "powershell/",   "libwww-perl/",
      "axios/",            "node-fetch/",   "undici"};

  return containsAnyUserAgentToken(lower, browser_tokens) ||
         containsAnyUserAgentToken(lower, inspection_tool_tokens);
}

static std::string providerUserAgentFromRequest(const Request &request) {
  auto ua = request.headers.find("User-Agent");
  if (ua == request.headers.end())
    return "";

  std::string value = trimProviderUserAgentCandidate(ua->second);
  if (value.empty() || value.size() > kProviderUserAgentMaxLen ||
      hasInvalidProviderUserAgentChar(value) ||
      isExcludedProviderUserAgent(value))
    return "";

  return value;
}

static bool isValidProviderHeaderName(const std::string &name) {
  if (name.empty() || name.size() > 128)
    return false;
  static const std::string punctuation = "!#$%&'*+-.^_`|~";
  for (unsigned char ch : name) {
    if (!std::isalnum(ch) && punctuation.find(ch) == std::string::npos)
      return false;
  }
  return true;
}

static bool isReservedProviderHeader(const std::string &name) {
  std::string lower = toLower(name);
  static const std::unordered_set<std::string> reserved = {
      "host",              "connection",        "keep-alive",
      "proxy-authenticate", "proxy-authorization", "te",
      "trailer",           "transfer-encoding", "upgrade",
      "content-length",    "cookie",            "forwarded",
      "origin",            "referer",           "user-agent",
      "x-age-public-key",  "if-match",          "if-none-match",
      "if-modified-since", "if-unmodified-since", "if-range",
      "range"};
  if (reserved.find(lower) != reserved.end())
    return true;

  static const string_array reserved_prefixes = {
      "cf-",          "sec-",        "x-forwarded-", "x-real-ip",
      "x-client-ip",  "x-original-", "x-envoy-",     "true-client-ip",
      "fastly-",      "fly-"};
  for (const std::string &prefix : reserved_prefixes) {
    if (startsWith(lower, prefix))
      return true;
  }
  return false;
}

static bool hasInvalidProviderHeaderValue(const std::string &value) {
  if (value.empty() || value.size() > 8192)
    return true;
  for (unsigned char ch : value) {
    if (ch == '\r' || ch == '\n' || ch == 0 || ch == 0x7f)
      return true;
  }
  return false;
}

static bool providerHeadersFromRequest(
    const Request &request, const std::string &selected,
    std::map<std::string, std::string> &headers, std::string &error) {
  headers.clear();
  if (selected.empty())
    return true;
  if (selected.size() > 1024) {
    error = "provider_headers is too long";
    return false;
  }

  std::unordered_set<std::string> seen;
  string_array names = split(selected, ",");
  if (names.empty() || names.size() > 16) {
    error = "provider_headers must select between 1 and 16 headers";
    return false;
  }
  for (std::string name : names) {
    name = trim(name);
    std::string lower = toLower(name);
    if (!isValidProviderHeaderName(name)) {
      error = "provider_headers contains an invalid header name";
      return false;
    }
    if (isReservedProviderHeader(name)) {
      error = "provider_headers contains a reserved header name: " + name;
      return false;
    }
    if (!seen.insert(lower).second) {
      error = "provider_headers contains a duplicate header name: " + name;
      return false;
    }

    auto iter = request.headers.find(name);
    if (iter == request.headers.end()) {
      error = "provider_headers selected a header that is missing: " + name;
      return false;
    }
    if (hasInvalidProviderHeaderValue(iter->second)) {
      error = "provider_headers selected an invalid header value: " + name;
      return false;
    }
    headers.emplace(iter->first, iter->second);
  }
  return true;
}

static void appendVaryHeader(Response &response, const std::string &field) {
  auto iter = response.headers.find("Vary");
  if (iter == response.headers.end() || iter->second.empty()) {
    response.headers["Vary"] = field;
    return;
  }

  std::string lower_field = toLower(field);
  for (std::string token : split(iter->second, ",")) {
    token = trim(token);
    if (toLower(token) == lower_field)
      return;
  }
  iter->second += ", " + field;
}

static std::string buildProviderRemarkFilter(const string_array &rules) {
  string_array valid_rules;
  for (const std::string &rule : rules) {
    if (!rule.empty() && regValid(rule))
      valid_rules.emplace_back(rule);
  }

  if (valid_rules.empty())
    return "";
  if (valid_rules.size() == 1)
    return valid_rules.front();

  return "(" + join(valid_rules, ")|(") + ")";
}

extern string_array ClashRuleTypes, SurgeRuleTypes, QuanXRuleTypes;

std::string getRuleset(RESPONSE_CALLBACK_ARGS) {
  SettingsSnapshot snapshot = captureEffectiveSettingsSnapshot();
  ScopedSettingsView settings_scope(std::move(snapshot));
  auto &argument = request.argument;
  int *status_code = &response.status_code;
  /// type: 1 for Surge, 2 for Quantumult X, 3 for Clash domain rule-provider, 4
  /// for Clash ipcidr rule-provider, 5 for Surge DOMAIN-SET, 6 for Clash
  /// classical ruleset
  std::string url = urlSafeBase64Decode(getUrlArg(argument, "url")),
              type = getUrlArg(argument, "type"),
              group = urlSafeBase64Decode(getUrlArg(argument, "group"));
  std::string output_content;
  int type_int = to_int(type, 0);

  if (url.empty() || type.empty() || (type_int == 2 && group.empty()) ||
      (type_int < 1 || type_int > 6)) {
    *status_code = 400;
    return "Invalid request: missing or invalid ruleset parameters.\n"
           "无效请求：规则集参数缺失或无效。\n"
           "Required: url and type=1..6; group is required when type=2.\n"
           "必须提供 url 和 type=1..6；当 type=2 时还必须提供 group。";
  }

  string_array vArray = split(url, "|");
  for (std::string &x : vArray)
    x.insert(0, "ruleset,");
  std::vector<RulesetContent> rca;
  RulesetConfigs confs = INIBinding::from<RulesetConfig>::from_ini(vArray);
  refreshRulesets(confs, rca, FetchContext::PublicRequest);
  for (RulesetContent &x : rca) {
    std::string content;
    try {
      content = waitWithoutCpuPermit([&] { return x.rule_content.get(); });
    } catch (const ExecutorSubmitError &error) {
      response.content_type = "text/plain; charset=utf-8";
      response.headers["Cache-Control"] = "private, no-store";
      switch (error.status()) {
      case ExecutorSubmitStatus::Deadline:
        *status_code = 504;
        if (request.context) {
          request.context->requestCancellation(
              RequestCancellationReason::Deadline);
          request.context->suggestFailure(RequestFailureAttribution::Client);
        }
        return "Gateway timeout: ruleset processing exceeded the request "
               "deadline.\n网关超时：规则集处理已超过请求截止时间。\n";
      case ExecutorSubmitStatus::Cancelled:
        if (request.context &&
            request.context->cancellationToken().reason() ==
                RequestCancellationReason::Shutdown) {
          *status_code = 503;
          request.context->suggestFailure(RequestFailureAttribution::Server);
          return "Service is shutting down.\n服务正在关闭。\n";
        }
        *status_code = 499;
        if (request.context)
          request.context->suggestFailure(RequestFailureAttribution::Client);
        return "Client closed request during ruleset processing.\n"
               "客户端在规则集处理期间关闭了请求。\n";
      case ExecutorSubmitStatus::QueueFull:
      case ExecutorSubmitStatus::Recursive:
        response.headers["Retry-After"] = "1";
        if (request.context)
          request.context->suggestFailure(RequestFailureAttribution::Capacity);
        *status_code = 503;
        return "Service temporarily unavailable: ruleset capacity is full.\n"
               "服务暂时不可用：规则集处理容量已满。\n";
      case ExecutorSubmitStatus::Stopping:
        *status_code = 503;
        if (request.context)
          request.context->suggestFailure(RequestFailureAttribution::Server);
        return "Service is shutting down.\n服务正在关闭。\n";
      case ExecutorSubmitStatus::Accepted:
        throw;
      }
    } catch (const std::future_error &) {
      *status_code = 503;
      response.content_type = "text/plain; charset=utf-8";
      response.headers["Cache-Control"] = "private, no-store";
      if (request.context)
        request.context->suggestFailure(RequestFailureAttribution::Server);
      return "Service is shutting down.\n服务正在关闭。\n";
    }
    output_content += convertRuleset(content, x.rule_type);
  }

  if (output_content.empty()) {
    *status_code = 400;
    return "Invalid request: no valid rules were found in the supplied "
           "ruleset source.\n"
           "无效请求：提供的规则集来源中未找到有效规则。\n"
           "Please check whether the URL is reachable and the ruleset type "
           "matches the content.\n"
           "请检查链接是否可访问，以及规则集类型是否与内容匹配。";
  }

  return formatRulesetOutput(
      std::move(output_content), type_int, group,
      RulesetTypeCatalogs{ClashRuleTypes, SurgeRuleTypes, QuanXRuleTypes});
}

bool checkExternalBase(const std::string &path, std::string &dest,
                       FetchContext context) {
  if (path.empty())
    return false;
  if (isLink(path)) {
    if (!isFetchUrlAllowed(path, context))
      return false;
    dest = path;
    return true;
  }
  if (fileExist(path, true) && isTrustedLocalResourcePath(path)) {
    dest = path;
    return true;
  }
  return false;
}

static const std::string *selectedExternalBase(const ExternalConfig &extconf,
                                               const std::string &target,
                                               bool simple_subscription,
                                               bool nodelist) {
  if (nodelist)
    return nullptr;
  if (target == "sssub")
    return &extconf.sssub_rule_base;
  if (simple_subscription)
    return nullptr;
  if (target == "clash" || target == "clashr")
    return &extconf.clash_rule_base;
  if (target == "surge")
    return &extconf.surge_rule_base;
  if (target == "surfboard")
    return &extconf.surfboard_rule_base;
  if (target == "stash")
    return &extconf.stash_rule_base;
  if (target == "mellow")
    return &extconf.mellow_rule_base;
  if (target == "quan")
    return &extconf.quan_rule_base;
  if (target == "quanx")
    return &extconf.quanx_rule_base;
  if (target == "loon")
    return &extconf.loon_rule_base;
  if (target == "singbox")
    return &extconf.singbox_rule_base;
  return nullptr;
}

static bool validateSelectedExternalBase(const ExternalConfig &extconf,
                                         const std::string &target,
                                         bool simple_subscription,
                                         bool nodelist,
                                         FetchContext context) {
  const std::string *base = selectedExternalBase(
      extconf, target, simple_subscription, nodelist);
  if (!base || base->empty())
    return true;
  std::string validated;
  return checkExternalBase(*base, validated, context);
}

static bool hasEffectiveExternalConfig(const ExternalConfig &extconf,
                                       const template_args &tpl_args,
                                       const string_map &tpl_args_base,
                                       const std::string &target) {
  if (tpl_args.local_vars != tpl_args_base)
    return true;

  if (!extconf.custom_proxy_group.empty() || !extconf.surge_ruleset.empty())
    return true;

  if (!extconf.rule_prepend_sources.empty() ||
      !extconf.rule_append_sources.empty())
    return true;

  if (!extconf.clash_rule_base.empty() || !extconf.surge_rule_base.empty() ||
      !extconf.surfboard_rule_base.empty() ||
      !extconf.mellow_rule_base.empty() || !extconf.quan_rule_base.empty() ||
      !extconf.quanx_rule_base.empty() || !extconf.loon_rule_base.empty() ||
      (target == "stash" && !extconf.stash_rule_base.empty()) ||
      !extconf.sssub_rule_base.empty() ||
      !extconf.singbox_rule_base.empty())
    return true;

  if (!extconf.rename.empty() || !extconf.emoji.empty() ||
      !extconf.include.empty() || !extconf.exclude.empty())
    return true;

  if (!extconf.add_emoji.is_undef() || !extconf.remove_old_emoji.is_undef())
    return true;

  if (!extconf.enable_rule_generator || extconf.overwrite_original_rules)
    return true;

  return false;
}

static bool fetchExternalRuleSources(const string_array &sources,
                                     const std::string &field_name,
                                     FetchContext context,
                                     string_array &destination,
                                     std::string &error) {
  const Settings &settings = effectiveSettings();
  ProxyPolicy proxy = parseProxy(settings.proxyRuleset, settings.proxyBypass);
  string_icase_map request_headers = {
      {"Cache-Control", "no-cache, no-store, max-age=0"},
      {"Pragma", "no-cache"}};

  for (size_t i = 0; i < sources.size(); ++i) {
    const std::string source_identifier =
        field_name + " source #" + std::to_string(i + 1);
    const std::string lower_source = toLower(sources[i]);
    if (!startsWith(lower_source, "http://") &&
        !startsWith(lower_source, "https://")) {
      error =
          "Invalid external rule source " + source_identifier +
          ": only remote HTTP(S) URLs are supported; local paths and data "
          "URLs are not allowed.\n"
          "外部规则来源 " +
          source_identifier +
          " 无效：仅支持远程 HTTP(S) URL，不允许本地路径或 data URL。";
      return false;
    }

    int fetch_status = 0;
    std::string content;
    FetchArgument argument{HTTP_GET,
                           sources[i],
                           proxy,
                           nullptr,
                           &request_headers,
                           nullptr,
                           0,
                           false,
                           context};
    FetchResult result{&fetch_status, &content, nullptr, nullptr};
    webGet(argument, result);
    if (fetch_status < 200 || fetch_status >= 300 || content.empty()) {
      writeLog(LOG_LEVEL_WARNING,
               "外部规则来源 " + source_identifier +
                   " 拉取失败、HTTP 状态异常或内容为空，已跳过。");
      continue;
    }

    ExternalRuleParseResult parsed =
        parseExternalClashRules(content, source_identifier, ClashRuleTypes);
    if (!parsed.ok) {
      error = std::move(parsed.error);
      return false;
    }
    if (parsed.rules.empty()) {
      error =
          "Invalid external rule source " + source_identifier +
          ": no usable rules were found.\n"
          "外部规则来源 " +
          source_identifier + " 无效：未找到可用规则。";
      return false;
    }
    destination.insert(destination.end(),
                       std::make_move_iterator(parsed.rules.begin()),
                       std::make_move_iterator(parsed.rules.end()));
  }
  return true;
}

/**
 * 根据订阅链接生成唯一特征码（MD5 前 6 位，大写）
 * @param url 订阅链接（会自动解码后计算哈希）
 * @return 6 位大写 hex 特征码字符串
 */
inline std::string generateProviderHash(const std::string &url) {
  std::string decodedUrl = urlDecode(url);
  std::string fullHash = getMD5(decodedUrl);
  std::string shortHash = fullHash.substr(0, 6);
  // 转换为大写
  std::transform(shortHash.begin(), shortHash.end(), shortHash.begin(),
                 ::toupper);
  return shortHash;
}

inline std::string generateProviderHashFromDecodedUrl(
    const std::string &decoded_url) {
  std::string fullHash = getMD5(decoded_url);
  std::string shortHash = fullHash.substr(0, 6);
  std::transform(shortHash.begin(), shortHash.end(), shortHash.begin(),
                 ::toupper);
  return shortHash;
}

struct TaggedLink {
  enum class Error {
    None,
    InvalidInterval,
    DuplicateInterval,
    InvalidProxyDirect,
    DuplicateProxyDirect,
    InvalidNode,
  };

  std::string tag;
  std::string provider;
  std::string link;
  int interval = 0;
  bool proxy_direct = kDefaultProxyProviderDirect;
  bool has_tag = false;
  bool has_provider = false;
  bool has_interval = false;
  bool has_proxy_direct = false;
  bool has_node = false;
  bool link_decoded = false;
  Error error = Error::None;
};

static bool extractLinkPrefix(const std::string &input,
                              const std::string &prefix,
                              std::string &value,
                              std::string &remainder,
                              bool &saw_bracketed) {
  std::string trimmed = trimWhitespace(input, true, true);
  size_t start = std::string::npos;
  bool bracketed = false;
  std::string bracket_prefix = "<" + prefix;
  if (startsWith(trimmed, bracket_prefix)) {
    start = bracket_prefix.size();
    bracketed = true;
  } else if (startsWith(trimmed, prefix)) {
    start = prefix.size();
  } else {
    return false;
  }

  size_t comma_pos = trimmed.find(',', start);
  if (comma_pos == std::string::npos)
    return false;

  value = trimmed.substr(start, comma_pos - start);
  size_t link_pos = comma_pos + 1;
  if (bracketed && link_pos < trimmed.size() && trimmed[link_pos] == '>')
    link_pos++;
  if (link_pos >= trimmed.size())
    return false;

  remainder = trimmed.substr(link_pos);
  if (bracketed)
    saw_bracketed = true;
  return true;
}

static bool parseLinkPrefixes(const std::string &input, TaggedLink &result) {
  std::string remainder = input;
  bool saw_bracketed = false;
  bool parsed = false;

  while (true) {
    std::string value;
    std::string next;
    if (extractLinkPrefix(remainder, "tag:", value, next, saw_bracketed)) {
      parsed = true;
      if (!value.empty() && !result.has_tag) {
        result.tag = value;
        result.has_tag = true;
      }
      remainder = next;
      continue;
    }
    if (extractLinkPrefix(remainder, "provider:", value, next, saw_bracketed)) {
      parsed = true;
      if (!value.empty() && !result.has_provider) {
        result.provider = value;
        result.has_provider = true;
      }
      remainder = next;
      continue;
    }
    if (extractLinkPrefix(remainder, "interval:", value, next,
                          saw_bracketed)) {
      parsed = true;
      if (result.has_interval) {
        result.error = TaggedLink::Error::DuplicateInterval;
        return true;
      }
      if (!parseProxyProviderInterval(value, result.interval)) {
        result.error = TaggedLink::Error::InvalidInterval;
        return true;
      }
      result.has_interval = true;
      remainder = next;
      continue;
    }
    if (extractLinkPrefix(remainder, "proxy_direct:", value, next,
                          saw_bracketed)) {
      parsed = true;
      if (result.has_proxy_direct) {
        result.error = TaggedLink::Error::DuplicateProxyDirect;
        return true;
      }
      if (!parseProxyProviderDirect(value, result.proxy_direct)) {
        result.error = TaggedLink::Error::InvalidProxyDirect;
        return true;
      }
      result.has_proxy_direct = true;
      remainder = next;
      continue;
    }
    if (startsWith(remainder, "node:")) {
      parsed = true;
      result.has_node = true;
      remainder.erase(0, 5);
      break;
    }
    break;
  }

  std::string lower_remainder =
      toLower(trimWhitespace(remainder, true, true));
  const bool starts_interval = startsWith(lower_remainder, "interval:") ||
                               startsWith(lower_remainder, "<interval:");
  const bool starts_proxy_direct =
      startsWith(lower_remainder, "proxy_direct:") ||
      startsWith(lower_remainder, "<proxy_direct:");
  if (starts_interval && lower_remainder.find("%2c") == std::string::npos) {
    result.error = TaggedLink::Error::InvalidInterval;
    return true;
  }
  if (starts_proxy_direct &&
      lower_remainder.find("%2c") == std::string::npos) {
    result.error = TaggedLink::Error::InvalidProxyDirect;
    return true;
  }

  if (!parsed)
    return false;

  remainder = trimWhitespace(remainder, true, true);
  if (saw_bracketed && !remainder.empty() && remainder.back() == '>')
    remainder.pop_back();
  result.link = remainder;
  if (result.has_node &&
      (result.has_provider || result.has_interval ||
       result.has_proxy_direct ||
       !mihomo::isExplicitHttpNodeUri(result.link)))
    result.error = TaggedLink::Error::InvalidNode;
  return true;
}

static bool looksLikeEncodedLinkPrefix(const std::string &input) {
  std::string lower = toLower(input);
  return startsWith(lower, "tag%3a") || startsWith(lower, "provider%3a") ||
         startsWith(lower, "interval%3a") ||
         startsWith(lower, "proxy_direct%3a") ||
         startsWith(lower, "node%3a") ||
         startsWith(lower, "%3ctag%3a") ||
         startsWith(lower, "%3cprovider%3a") || startsWith(lower, "%3ctag:") ||
         startsWith(lower, "%3cinterval%3a") ||
         startsWith(lower, "%3cproxy_direct%3a") ||
         startsWith(lower, "%3cprovider:") ||
         startsWith(lower, "%3cinterval:") ||
         startsWith(lower, "%3cproxy_direct:") ||
         (startsWith(lower, "tag:") &&
          lower.find("%2c") != std::string::npos) ||
         (startsWith(lower, "provider:") &&
          lower.find("%2c") != std::string::npos) ||
         (startsWith(lower, "interval:") &&
          lower.find("%2c") != std::string::npos) ||
         (startsWith(lower, "proxy_direct:") &&
          lower.find("%2c") != std::string::npos);
}

static TaggedLink parseTaggedLink(const std::string &input) {
  TaggedLink result;
  std::string value = trimWhitespace(input, true, true);
  if (parseLinkPrefixes(value, result))
    return result;
  if (looksLikeEncodedLinkPrefix(value)) {
    TaggedLink decoded_result;
    std::string decoded = urlDecode(value);
    if (parseLinkPrefixes(decoded, decoded_result)) {
      decoded_result.link_decoded = true;
      return decoded_result;
    }
  }
  result.link = value;
  return result;
}

static std::string providerLinkPrefixError(
    size_t item_index, TaggedLink::Error error) {
  const std::string item = std::to_string(item_index + 1);
  if (error == TaggedLink::Error::InvalidNode) {
    return "Invalid request: node: for URL item #" + item +
           " requires an HTTP(S) proxy with a host and port, no credentials, "
           "path, or query, and no provider-only prefixes.\n"
           "无效请求：第 " + item +
           " 个 url 项的 node: 必须是带主机和端口的 HTTP(S) 代理链接，"
           "不得带认证信息、路径、查询参数或 Provider 专用前缀。";
  }
  if (error == TaggedLink::Error::DuplicateInterval) {
    return "Invalid request: interval: is repeated for URL item #" + item +
           ".\n"
           "无效请求：第 " + item +
           " 个 url 项重复设置了 interval: 前缀。";
  }
  if (error == TaggedLink::Error::InvalidInterval) {
    return "Invalid request: interval: for URL item #" + item +
           " must be a decimal integer from 0 to 2147483647.\n"
           "无效请求：第 " + item +
           " 个 url 项的 interval: 必须是 0 到 2147483647 之间的十进制整数。";
  }
  if (error == TaggedLink::Error::DuplicateProxyDirect) {
    return "Invalid request: proxy_direct: is repeated for URL item #" + item +
           ".\n"
           "无效请求：第 " + item +
           " 个 url 项重复设置了 proxy_direct: 前缀。";
  }
  return "Invalid request: proxy_direct: for URL item #" + item +
         " must be true, false, 1, or 0.\n"
         "无效请求：第 " + item +
         " 个 url 项的 proxy_direct: 必须是 true、false、1 或 0。";
}

static std::string providerIntervalScopeError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: interval: for URL item #" + item +
         " is only valid for subscription links that generate Clash/ClashR "
         "proxy-providers, Quantumult X server_remote resources, Surge "
         "policy-path resources, or Stash proxy-providers.\n"
         "无效请求：第 " + item +
         " 个 url 项的 interval: 仅适用于会生成 Clash/ClashR "
         "proxy-provider、Quantumult X server_remote、Surge policy-path "
         "或 Stash proxy-provider 资源的订阅链接。";
}

static std::string providerDirectScopeError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: proxy_direct: for URL item #" + item +
         " is only valid for subscription links that generate Clash/ClashR "
         "proxy-providers.\n"
         "无效请求：第 " + item +
         " 个 url 项的 proxy_direct: 仅适用于会生成 Clash/ClashR "
         "proxy-provider 的订阅链接。";
}

static std::string quanxRemoteSourceError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: Quantumult X remote subscription item #" + item +
         " contains an unescaped space or control character.\n"
         "无效请求：第 " + item +
         " 个 Quantumult X 远程订阅项包含未转义空格或控制字符。";
}

static std::string surgePolicyPathSourceError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: Surge policy-path subscription item #" + item +
         " contains an unescaped space or control character.\n"
         "无效请求：第 " + item +
         " 个 Surge policy-path 订阅项包含未转义空格或控制字符。";
}

static std::string surfboardPolicyPathSourceError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: Surfboard policy-path subscription item #" + item +
         " contains an unescaped space or control character.\n"
         "无效请求：第 " + item +
         " 个 Surfboard policy-path 订阅项包含未转义空格或控制字符。";
}

static std::string loonRemoteProxySourceError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: Loon Remote Proxy subscription item #" + item +
         " contains an unescaped space or control character.\n"
         "无效请求：第 " + item +
         " 个 Loon Remote Proxy 订阅项包含未转义空格或控制字符。";
}

static std::string stashProxyProviderSourceError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: Stash proxy-provider subscription item #" + item +
         " contains an unescaped space or control character.\n"
         "无效请求：第 " + item +
         " 个 Stash proxy-provider 订阅项包含未转义空格或控制字符。";
}

static std::string surgePolicyPathIntervalError(size_t item_index) {
  const std::string item = std::to_string(item_index + 1);
  return "Invalid request: interval: for Surge policy-path item #" + item +
         " must be greater than zero. Omit it to use the client default.\n"
         "无效请求：第 " + item +
         " 个 Surge policy-path 项的 interval: 必须大于 0；省略该前缀可使用客户端默认值。";
}

static constexpr size_t kProviderNameMaxLen = 64;

static bool isWindowsReservedName(const std::string &name) {
  if (name.empty())
    return false;
  std::string trimmed = trimWhitespace(name, true, true);
  trimmed = trimOf(trimmed, '.', true, true);
  if (trimmed.empty())
    return false;
  std::string upper = toUpper(trimmed);
  string_size dot_pos = upper.find('.');
  std::string base =
      dot_pos == std::string::npos ? upper : upper.substr(0, dot_pos);
  static const std::unordered_set<std::string> reserved = {
      "CON",  "PRN",  "AUX",  "NUL",  "COM1", "COM2", "COM3", "COM4",
      "COM5", "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3",
      "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"};
  return reserved.find(base) != reserved.end();
}

static std::string clampProviderNameLength(const std::string &name,
                                           size_t max_len) {
  if (name.size() <= max_len)
    return name;
  std::string truncated = name.substr(0, max_len);
  while (!truncated.empty() && !isStrUTF8(truncated))
    truncated.pop_back();
  return truncated;
}

static std::string sanitizeProviderName(const std::string &input) {
  std::string name = trimWhitespace(input, true, true);
  if (name.empty())
    return "";

  std::string cleaned;
  cleaned.reserve(name.size());
  bool last_was_underscore = false;
  char last_out = '\0';

  for (unsigned char c : name) {
    bool invalid = false;
    if (c < 0x20 || c == 0x7F)
      invalid = true;
    if (!invalid) {
      switch (c) {
      case '<':
      case '>':
      case ':':
      case '"':
      case '/':
      case '\\':
      case '|':
      case '?':
      case '*':
        invalid = true;
        break;
      default:
        break;
      }
    }
    if (!invalid && c == '.' && last_out == '.')
      invalid = true;
    if (!invalid && c == '_')
      invalid = true;

    if (invalid) {
      if (!last_was_underscore) {
        cleaned.push_back('_');
        last_was_underscore = true;
        last_out = '_';
      }
      continue;
    }

    cleaned.push_back(static_cast<char>(c));
    last_was_underscore = false;
    last_out = static_cast<char>(c);
  }

  cleaned = trimWhitespace(cleaned, true, true);
  cleaned = trimOf(cleaned, '.', true, true);
  if (cleaned.empty() || isWindowsReservedName(cleaned))
    return "";

  cleaned = clampProviderNameLength(cleaned, kProviderNameMaxLen);
  cleaned = trimOf(cleaned, '.', true, true);
  if (cleaned.empty() || isWindowsReservedName(cleaned))
    return "";

  return cleaned;
}

static std::string subconverter_impl(Request &request, Response &response,
                                     RuleConversionStats *rule_stats = nullptr);

namespace {

struct CoalescedResponse {
  int status_code = 200;
  std::string content_type;
  string_icase_map headers;
  std::string body;
  uint64_t rule_conversions = 0;
};

using SharedCoalescedResponse = std::shared_ptr<const CoalescedResponse>;

struct InflightSubRequest {
  std::mutex mutex;
  std::condition_variable cv;
  bool done = false;
  SharedCoalescedResponse result;
  std::exception_ptr exception;
};

struct CachedSubResponse {
  SharedCoalescedResponse result;
  std::chrono::steady_clock::time_point expires_at;
};

static std::mutex g_sub_inflight_mutex;
static std::map<std::string, std::shared_ptr<InflightSubRequest>>
    g_sub_inflight;
static std::mutex g_sub_response_cache_mutex;
static std::map<std::string, CachedSubResponse> g_sub_response_cache;

struct SubExplainProvider {
  std::string name;
  std::string tag;
  std::string source_hash;
  std::string path;
  std::string filter;
  std::string exclude_filter;
  int group_id = 0;
  uint32_t interval = 0;
};

struct SubExplainParameter {
  std::string name;
  std::string source;
  std::string status;
  std::string value_preview;
  std::string value_hash;
  std::string effective_value;
  std::string note;
  size_t raw_length = 0;
  size_t value_length = 0;
  bool present = false;
  bool sensitive = false;
};

struct SubExplainConfigSection {
  std::string name;
  std::string source;
  std::string status;
  std::string detail;
};

struct SubExplainReport {
  bool enabled = false;
  std::string requested_target;
  std::string target;
  bool simple_subscription = false;
  bool upload_requested = false;
  bool upload_suppressed = false;
  bool external_config_provided = false;
  bool external_config_loaded = false;
  bool fallback_config_used = false;
  bool rule_generator_enabled = false;
  bool expand_rulesets = false;
  bool proxy_provider_mode = false;
  bool nodelist = false;
  bool managed_config = false;
  std::string proxy_config;
  std::string proxy_ruleset;
  std::string proxy_subscription;
  std::string base_fetch_context = "trusted_config";
  std::string ruleset_fetch_context = "trusted_config";
  size_t raw_url_count = 0;
  size_t insert_url_count = 0;
  size_t subscription_url_count = 0;
  size_t node_link_count = 0;
  size_t unknown_node_link_count = 0;
  size_t provider_count = 0;
  size_t insert_node_count = 0;
  size_t direct_node_count = 0;
  size_t total_node_count = 0;
  size_t ruleset_count = 0;
  size_t custom_group_count = 0;
  size_t output_bytes = 0;
  std::vector<SubExplainProvider> providers;
  std::vector<SubExplainParameter> recognized_parameters;
  std::vector<SubExplainParameter> unrecognized_parameters;
  std::string effective_config_source = "none";
  std::vector<SubExplainConfigSection> effective_config_sections;
};

static std::string fetchContextName(FetchContext context) {
  switch (context) {
  case FetchContext::PublicRequest:
    return "public_request";
  case FetchContext::TrustedConfig:
  default:
    return "trusted_config";
  }
}

static std::string shortHash(const std::string &value) {
  if (value.empty())
    return "";
  return getMD5(value).substr(0, 10);
}

static std::string boolString(bool value) { return value ? "true" : "false"; }

static std::string previewExplainValue(const std::string &raw_value,
                                       bool sensitive) {
  std::string decoded = urlDecode(raw_value);
  if (decoded.empty())
    return "";
  if (sensitive)
    return "[redacted]";

  static constexpr size_t kMaxPreview = 180;
  if (decoded.size() <= kMaxPreview)
    return decoded;
  return decoded.substr(0, kMaxPreview) + "...";
}

static void writeJsonString(
    rapidjson::Writer<rapidjson::StringBuffer> &writer, const char *key,
    const std::string &value) {
  writer.Key(key);
  writer.String(value.c_str());
}

static void writeExplainParameter(
    rapidjson::Writer<rapidjson::StringBuffer> &writer,
    const SubExplainParameter &parameter) {
  writer.StartObject();
  writeJsonString(writer, "name", parameter.name);
  writer.Key("present");
  writer.Bool(parameter.present);
  writeJsonString(writer, "source", parameter.source);
  writeJsonString(writer, "status", parameter.status);
  writeJsonString(writer, "value_preview", parameter.value_preview);
  writeJsonString(writer, "value_hash", parameter.value_hash);
  writer.Key("raw_length");
  writer.Uint64(parameter.raw_length);
  writer.Key("value_length");
  writer.Uint64(parameter.value_length);
  writeJsonString(writer, "effective_value", parameter.effective_value);
  writeJsonString(writer, "note", parameter.note);
  writer.Key("sensitive");
  writer.Bool(parameter.sensitive);
  writer.EndObject();
}

static void writeExplainConfigSection(
    rapidjson::Writer<rapidjson::StringBuffer> &writer,
    const SubExplainConfigSection &section) {
  writer.StartObject();
  writeJsonString(writer, "name", section.name);
  writeJsonString(writer, "source", section.source);
  writeJsonString(writer, "status", section.status);
  writeJsonString(writer, "detail", section.detail);
  writer.EndObject();
}

static std::string serializeSubExplainReport(const SubExplainReport &report,
                                             const Response &response) {
  rapidjson::StringBuffer buffer;
  rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);

  writer.StartObject();
  writer.Key("ok");
  writer.Bool(response.status_code >= 200 && response.status_code < 300);
  writer.Key("status_code");
  writer.Int(response.status_code);
  writeJsonString(writer, "requested_target", report.requested_target);
  writeJsonString(writer, "target", report.target);

  writer.Key("mode");
  writer.StartObject();
  writer.Key("simple_subscription");
  writer.Bool(report.simple_subscription);
  writer.Key("proxy_provider");
  writer.Bool(report.proxy_provider_mode);
  writer.Key("nodelist");
  writer.Bool(report.nodelist);
  writer.Key("expand_rulesets");
  writer.Bool(report.expand_rulesets);
  writer.Key("rule_generator");
  writer.Bool(report.rule_generator_enabled);
  writer.Key("managed_config");
  writer.Bool(report.managed_config);
  writer.Key("upload_requested");
  writer.Bool(report.upload_requested);
  writer.Key("upload_suppressed");
  writer.Bool(report.upload_suppressed);
  writer.EndObject();

  writer.Key("inputs");
  writer.StartObject();
  writer.Key("raw_url_count");
  writer.Uint64(report.raw_url_count);
  writer.Key("insert_url_count");
  writer.Uint64(report.insert_url_count);
  writer.Key("subscription_url_count");
  writer.Uint64(report.subscription_url_count);
  writer.Key("node_link_count");
  writer.Uint64(report.node_link_count);
  writer.Key("unknown_node_link_count");
  writer.Uint64(report.unknown_node_link_count);
  writer.EndObject();

  writer.Key("external_config");
  writer.StartObject();
  writer.Key("provided");
  writer.Bool(report.external_config_provided);
  writer.Key("loaded");
  writer.Bool(report.external_config_loaded);
  writer.Key("fallback_used");
  writer.Bool(report.fallback_config_used);
  writer.EndObject();

  writer.Key("parameters");
  writer.StartObject();
  writer.Key("recognized");
  writer.StartArray();
  for (const SubExplainParameter &parameter : report.recognized_parameters)
    writeExplainParameter(writer, parameter);
  writer.EndArray();
  writer.Key("unrecognized");
  writer.StartArray();
  for (const SubExplainParameter &parameter : report.unrecognized_parameters)
    writeExplainParameter(writer, parameter);
  writer.EndArray();
  writer.EndObject();

  writer.Key("effective_config");
  writer.StartObject();
  writeJsonString(writer, "source", report.effective_config_source);
  writer.Key("sections");
  writer.StartArray();
  for (const SubExplainConfigSection &section :
       report.effective_config_sections)
    writeExplainConfigSection(writer, section);
  writer.EndArray();
  writer.EndObject();

  writer.Key("outbound_proxy");
  writer.StartObject();
  writeJsonString(writer, "config", report.proxy_config);
  writeJsonString(writer, "ruleset", report.proxy_ruleset);
  writeJsonString(writer, "subscription", report.proxy_subscription);
  writer.EndObject();

  writer.Key("resources");
  writer.StartObject();
  writeJsonString(writer, "base_fetch_context", report.base_fetch_context);
  writeJsonString(writer, "ruleset_fetch_context", report.ruleset_fetch_context);
  writer.Key("ruleset_count");
  writer.Uint64(report.ruleset_count);
  writer.Key("custom_group_count");
  writer.Uint64(report.custom_group_count);
  writer.EndObject();

  writer.Key("nodes");
  writer.StartObject();
  writer.Key("insert");
  writer.Uint64(report.insert_node_count);
  writer.Key("direct");
  writer.Uint64(report.direct_node_count);
  writer.Key("total");
  writer.Uint64(report.total_node_count);
  writer.EndObject();

  writer.Key("providers");
  writer.StartArray();
  for (const SubExplainProvider &provider : report.providers) {
    writer.StartObject();
    writeJsonString(writer, "name", provider.name);
    writeJsonString(writer, "tag", provider.tag);
    writeJsonString(writer, "source_hash", provider.source_hash);
    writeJsonString(writer, "path", provider.path);
    writeJsonString(writer, "filter", provider.filter);
    writeJsonString(writer, "exclude_filter", provider.exclude_filter);
    writer.Key("group_id");
    writer.Int(provider.group_id);
    writer.Key("interval");
    writer.Uint(provider.interval);
    writer.EndObject();
  }
  writer.EndArray();

  writer.Key("output");
  writer.StartObject();
  writer.Key("bytes");
  writer.Uint64(report.output_bytes);
  writer.Key("provider_count");
  writer.Uint64(report.provider_count);
  writer.EndObject();

  writer.EndObject();
  return buffer.GetString();
}

static bool isTruthyRequestValue(const std::string &value) {
  std::string normalized = toLower(trimWhitespace(value, true, true));
  return normalized == "1" || normalized == "true" ||
         normalized == "yes" || normalized == "on";
}

struct AgeResponseContext {
  bool requested = false;
  bool valid = true;
  std::string recipient;
  std::string fingerprint;
};

static AgeResponseContext consumeAgeResponseContext(Request &request) {
  AgeResponseContext context;
  auto iter = request.headers.find("X-Age-Public-Key");
  if (iter == request.headers.end())
    return context;

  context.requested = true;
  std::string supplied_key = std::move(iter->second);
  request.headers.erase(iter);
  try {
    mihomo::AgeRecipient resolved = mihomo::resolveAgeRecipient(supplied_key);
    context.recipient = std::move(resolved.recipient);
    context.fingerprint = std::move(resolved.fingerprint);
  } catch (...) {
    context.valid = false;
  }
  std::fill(supplied_key.begin(), supplied_key.end(), '\0');
  supplied_key.clear();
  return context;
}

static std::string rejectAgeRequest(Response &response,
                                    const std::string &message) {
  response.status_code = 400;
  response.content_type = "text/plain; charset=utf-8";
  response.headers["Cache-Control"] = "private, no-store";
  response.headers["X-SCE-Age"] = "rejected";
  appendVaryHeader(response, "X-Age-Public-Key");
  return message;
}

static std::string finalizeSubResponse(const Request &request,
                                       Response &response, std::string body,
                                       const AgeResponseContext &age) {
  // Every /sub representation varies on this header, including the plaintext
  // variant, so shared caches cannot serve plaintext to an encrypted request.
  appendVaryHeader(response, "X-Age-Public-Key");
  if (!age.requested)
    return body;

  response.headers["Cache-Control"] = "private, no-store";
  response.headers["X-SCE-Age-Recipient"] = age.fingerprint;
  if (response.status_code < 200 || response.status_code >= 300) {
    response.headers["X-SCE-Age"] = "error-not-encrypted";
    return body;
  }
  if (request.method == "HEAD" ||
      isTruthyRequestValue(getUrlArg(request.argument, "explain"))) {
    response.headers["X-SCE-Age"] = "diagnostic-not-encrypted";
    return body;
  }

  try {
    body = mihomo::encryptAgeArmored(body, age.recipient);
    response.headers.erase("ETag");
    response.headers.erase("Content-MD5");
    response.headers.erase("Digest");
    response.headers["X-SCE-Age"] = "encrypted";
    return body;
  } catch (...) {
    response.status_code = 500;
    response.content_type = "text/plain; charset=utf-8";
    response.headers.erase("Subscription-UserInfo");
    response.headers.erase("Content-Disposition");
    response.headers["X-SCE-Age"] = "encryption-failed";
    return "Internal error: Age response encryption failed.\n"
           "内部错误：Age 响应加密失败。";
  }
}

class SubRequestKeyBuilder {
public:
  bool append(const std::string &name, const std::string &value) {
    static constexpr size_t kMaxIdentitySize = 2 * 1024 * 1024;
    size_t extra_size = name.size() + value.size() + 32;
    if (size_ + extra_size > kMaxIdentitySize)
      return false;

    std::string value_size = std::to_string(value.size());
    process(name);
    process(":", 1);
    process(value_size);
    process(":", 1);
    process(value);
    process("\n", 1);
    size_ += name.size() + value_size.size() + value.size() + 3;
    return true;
  }

  std::string finish() {
    char digest[MD5_STRING_SIZE];
    md5_.finish();
    md5_.get_string(digest);
    return digest;
  }

private:
  void process(const std::string &value) {
    process(value.data(), value.size());
  }

  void process(const char *value, size_t size) {
    md5_.process(value, static_cast<uint32_t>(size));
  }

  md5::md5_t md5_;
  size_t size_ = 0;
};

static bool shouldCoalesceSubRequest(const Request &request) {
  if (!global.enableRequestCoalescing)
    return false;
  if (request.method != "GET" || request.url != "/sub")
    return false;
  if (isTruthyRequestValue(getUrlArg(request.argument, "upload")))
    return false;
  return true;
}

static std::string buildSubRequestKey(const Request &request,
                                      const AgeResponseContext &age) {
  SubRequestKeyBuilder identity;
  if (!identity.append("version", VERSION) ||
      !identity.append("config_generation",
                       std::to_string(global.configGeneration)) ||
      !identity.append("managed_config_prefix", global.managedConfigPrefix) ||
      !identity.append("method", request.method) ||
      !identity.append("path", request.url) ||
      !identity.append("age_recipient_fingerprint", age.fingerprint))
    return "";

  for (const auto &arg : request.argument) {
    if (!identity.append("arg_name", arg.first) ||
        !identity.append("arg_value", arg.second))
      return "";
  }

  for (const auto &header : request.headers) {
    if (!identity.append("header_name", toLower(header.first)) ||
        !identity.append("header_value", header.second))
      return "";
  }

  return identity.finish();
}

static void copyCoalescedToResponse(const CoalescedResponse &result,
                                    Response &response) {
  response.status_code = result.status_code;
  response.content_type = result.content_type;
  response.headers = result.headers;
}

static SharedCoalescedResponse makeCoalescedResult(
    std::string &&body, Response &&response, uint64_t rule_conversions) {
  auto result = std::make_shared<CoalescedResponse>();
  result->status_code = response.status_code;
  result->content_type = std::move(response.content_type);
  result->headers = std::move(response.headers);
  result->body = std::move(body);
  result->rule_conversions = rule_conversions;
  return result;
}

static void pruneExpiredSubResponseCache(
    std::chrono::steady_clock::time_point now) {
  for (auto iter = g_sub_response_cache.begin();
       iter != g_sub_response_cache.end();) {
    if (iter->second.expires_at <= now)
      iter = g_sub_response_cache.erase(iter);
    else
      ++iter;
  }
}

static bool getCachedSubResponse(const std::string &key,
                                 SharedCoalescedResponse &result) {
  if (global.responseCacheTtl <= 0)
    return false;

  auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(g_sub_response_cache_mutex);
  auto iter = g_sub_response_cache.find(key);
  if (iter == g_sub_response_cache.end())
    return false;
  if (iter->second.expires_at <= now) {
    g_sub_response_cache.erase(iter);
    return false;
  }
  result = iter->second.result;
  return true;
}

static void storeCachedSubResponse(const std::string &key,
                                   const SharedCoalescedResponse &result) {
  if (global.responseCacheTtl <= 0 || !result || result->status_code != 200)
    return;

  int ttl = std::min(global.responseCacheTtl, 5);
  if (ttl <= 0)
    return;

  auto now = std::chrono::steady_clock::now();
  std::lock_guard<std::mutex> lock(g_sub_response_cache_mutex);
  pruneExpiredSubResponseCache(now);
  if (g_sub_response_cache.size() > 2048) {
    writeLog(0,
             "响应微缓存条目数量过多，已清空以避免占用过多内存。",
             LOG_LEVEL_WARNING);
    g_sub_response_cache.clear();
  }
  g_sub_response_cache[key] = {
      result, now + std::chrono::seconds(ttl)};
}

static std::string runSubconverterImplWithRetry(const Request &original,
                                                Response &response,
                                                RuleConversionStats *stats) {
  Request first_request = original;
  Response first_response;
  RuleConversionStats first_stats;
  std::string body = subconverter_impl(first_request, first_response,
                                       stats ? &first_stats : nullptr);
  if (first_response.status_code < 500 || !global.coalesceRetryOn5xx) {
    if (stats)
      *stats = first_stats;
    response = first_response;
    return body;
  }

  writeLog(0,
           "/sub 请求首次转换返回 5xx，正在进行一次服务端内部重试。",
           LOG_LEVEL_WARNING);
  Request retry_request = original;
  Response retry_response;
  RuleConversionStats retry_stats;
  std::string retry_body = subconverter_impl(retry_request, retry_response,
                                             stats ? &retry_stats : nullptr);
  if (retry_response.status_code < 500) {
    if (stats)
      *stats = retry_stats;
    response = retry_response;
    return retry_body;
  }

  if (stats)
    *stats = first_stats;
  response = first_response;
  return body;
}

static void recordTrackedSubRequest(bool track, const Request &request,
                                    const Response &response,
                                    uint64_t rule_conversions) {
  if (!track)
    return;
  if (response.status_code < 200 || response.status_code >= 300)
    return;
  statistics::recordSubscriptionConversion(request, rule_conversions);
}

static std::string subconverterEntry(Request &request, Response &response,
                                     bool track) {
  AgeResponseContext age = consumeAgeResponseContext(request);
  if (age.requested && !age.valid) {
    return rejectAgeRequest(
        response,
        "Invalid X-Age-Public-Key: expected one Mihomo-supported Age public "
        "or secret key.\n"
        "X-Age-Public-Key 无效：应提供一个 Mihomo 支持的 Age 公钥或私钥。"
    );
  }
  if (age.requested && getUrlArg(request.argument, "target") != "clash") {
    return rejectAgeRequest(
        response,
        "Invalid request: Age response encryption is supported only for "
        "target=clash.\n"
        "无效请求：Age 响应加密仅支持 target=clash。"
    );
  }

  if (!shouldCoalesceSubRequest(request)) {
    RuleConversionStats stats;
    std::string body =
        subconverter_impl(request, response, track ? &stats : nullptr);
    body = finalizeSubResponse(request, response, std::move(body), age);
    recordTrackedSubRequest(track, request, response, stats.rules);
    return body;
  }

  std::string key = buildSubRequestKey(request, age);
  if (key.empty()) {
    RuleConversionStats stats;
    std::string body =
        subconverter_impl(request, response, track ? &stats : nullptr);
    body = finalizeSubResponse(request, response, std::move(body), age);
    recordTrackedSubRequest(track, request, response, stats.rules);
    return body;
  }

  SharedCoalescedResponse cached_result;
  if (getCachedSubResponse(key, cached_result)) {
    writeLog(0, "/sub 响应微缓存命中。", LOG_LEVEL_DEBUG);
    copyCoalescedToResponse(*cached_result, response);
    recordTrackedSubRequest(track, request, response,
                            cached_result->rule_conversions);
    return cached_result->body;
  }

  std::shared_ptr<InflightSubRequest> call;
  bool owner = false;
  {
    std::lock_guard<std::mutex> lock(g_sub_inflight_mutex);
    auto iter = g_sub_inflight.find(key);
    if (iter == g_sub_inflight.end()) {
      call = std::make_shared<InflightSubRequest>();
      g_sub_inflight.emplace(key, call);
      owner = true;
    } else {
      call = iter->second;
    }
  }

  if (!owner) {
    writeLog(0, "/sub 请求已合并到正在执行的同 key 转换。",
             LOG_LEVEL_DEBUG);
    std::unique_lock<std::mutex> lock(call->mutex);
    call->cv.wait(lock, [&call] { return call->done; });
    if (call->exception)
      std::rethrow_exception(call->exception);
    copyCoalescedToResponse(*call->result, response);
    recordTrackedSubRequest(track, request, response,
                            call->result->rule_conversions);
    return call->result->body;
  }

  try {
    writeLog(0, "/sub 请求成为同 key 转换 owner。", LOG_LEVEL_DEBUG);
    Response owner_response;
    RuleConversionStats stats;
    std::string body = runSubconverterImplWithRetry(
        request, owner_response, track ? &stats : nullptr);
    body = finalizeSubResponse(request, owner_response, std::move(body), age);
    SharedCoalescedResponse result = makeCoalescedResult(
        std::move(body), std::move(owner_response), stats.rules);
    copyCoalescedToResponse(*result, response);
    {
      std::lock_guard<std::mutex> lock(call->mutex);
      call->result = result;
      call->done = true;
    }
    {
      std::lock_guard<std::mutex> lock(g_sub_inflight_mutex);
      g_sub_inflight.erase(key);
    }
    if (!age.requested)
      storeCachedSubResponse(key, result);
    call->cv.notify_all();
    recordTrackedSubRequest(track, request, response,
                            result->rule_conversions);
    return result->body;
  } catch (...) {
    {
      std::lock_guard<std::mutex> lock(call->mutex);
      call->exception = std::current_exception();
      call->done = true;
    }
    {
      std::lock_guard<std::mutex> lock(g_sub_inflight_mutex);
      g_sub_inflight.erase(key);
    }
    call->cv.notify_all();
    throw;
  }
}

} // namespace

std::string subconverter(RESPONSE_CALLBACK_ARGS) {
  return subconverterEntry(request, response, false);
}

std::string subconverterTracked(RESPONSE_CALLBACK_ARGS) {
  return subconverterEntry(request, response, true);
}

static std::string subconverter_impl(Request &request, Response &response,
                                     RuleConversionStats *rule_stats) {
  auto &argument = request.argument;
  parsed.target = getUrlArg(argument, "target");
  parsed.surge_version_text = getUrlArg(argument, "ver");
  parsed.explain_mode = isTruthyRequestValue(getUrlArg(argument, "explain"));
  parsed.explain.enabled = parsed.explain_mode;
  parsed.explain.proxy_config =
      parseProxy(settings.proxyConfig, settings.proxyBypass).describe();
  parsed.explain.proxy_ruleset =
      parseProxy(settings.proxyRuleset, settings.proxyBypass).describe();
  parsed.explain.proxy_subscription =
      parseProxy(settings.proxySubscription, settings.proxyBypass).describe();
  parsed.explain.proxy_bypass =
      ProxyBypassPolicy::parse(settings.proxyBypass).describe();
  parsed.explain.requested_target = parsed.target;
  if (parsed.explain_mode) {
    std::string rawUrlForLog = getUrlArg(argument, "url");
    const bool target_is_known = parsed.target == "auto" ||
                                 findTargetDescriptor(parsed.target) != nullptr;
    writeLog(LOG_LEVEL_INFO,
             "EXPLAIN_REQUEST_RECEIVED requested_target=" +
                  (parsed.target.empty() ? std::string("<empty>")
                   : (target_is_known ? parsed.target
                                      : std::string("<unsupported>"))) +
                  " parameter_count=" + std::to_string(argument.size()) +
                  " url_length=" + std::to_string(rawUrlForLog.size()));
  }

  std::string argTarget = getUrlArg(argument, "target"),
              argSurgeVer = getUrlArg(argument, "ver");
  bool explainMode = isTruthyRequestValue(getUrlArg(argument, "explain"));
  SubExplainReport explain;
  explain.enabled = explainMode;
  explain.proxy_config = parseProxy(global.proxyConfig).describe();
  explain.proxy_ruleset = parseProxy(global.proxyRuleset).describe();
  explain.proxy_subscription = parseProxy(global.proxySubscription).describe();
  explain.requested_target = argTarget;
  if (explainMode) {
    std::string rawUrlForLog = getUrlArg(argument, "url");
    writeLog(0,
             "收到 /sub explain JSON 诊断请求：target=" +
                 (argTarget.empty() ? std::string("<empty>") : argTarget) +
                 ", 参数数量=" + std::to_string(argument.size()) +
                 ", url_hash=" +
                 (rawUrlForLog.empty() ? std::string("-")
                                       : shortHash(urlDecode(rawUrlForLog))) +
                 "。",
             LOG_LEVEL_INFO);
  }
  tribool argClashNewField = getUrlArg(argument, "new_name");
  int intSurgeVer = !argSurgeVer.empty() ? to_int(argSurgeVer, 3) : 3;
  if (argTarget == "auto")
    matchUserAgent(request.headers["User-Agent"], argTarget, argClashNewField,
                   intSurgeVer);
  explain.target = argTarget;

  parsed.target_descriptor = findTargetDescriptor(parsed.target);
  if (!parsed.target_descriptor) {
    if (parsed.target_was_auto)
      writeLog(LOG_LEVEL_WARNING,
               "AUTO_TARGET_UNRESOLVED ua_family=unknown");
    response.status_code = 400;
    return "Invalid request: unsupported target value.\n"
           "无效请求：不支持的 target 参数值。\n"
           "Supported targets: " +
           supportedTargets(", ") + ".\n" + "支持的 target：" +
           supportedTargets("、") + "。";
  }
  parsed.simple_subscription = parsed.target_descriptor->simple_subscription;
  parsed.explain.remote_subscription_backend = remoteSubscriptionModeName(
      parsed.target_descriptor->remote_subscription_mode);
  if (parsed.target_was_auto) {
    writeLog(LOG_LEVEL_INFO,
             "AUTO_TARGET_RESOLVED target=" + parsed.target +
                 " parser=" +
                 nodeParserModeName(parsed.target_descriptor->parser_mode) +
                 " ua_family=" + parsed.user_agent_match.family);
  }

  /// string values
  std::string argUrl = getUrlArg(argument, "url");
  std::string argGroupName = getUrlArg(argument, "group"),
              argUploadPath = getUrlArg(argument, "upload_path");
  std::string argIncludeRemark = getUrlArg(argument, "include"),
              argExcludeRemark = getUrlArg(argument, "exclude");
  std::string argCustomGroups =
                  urlSafeBase64Decode(getUrlArg(argument, "groups")),
              argCustomRulesets =
                  urlSafeBase64Decode(getUrlArg(argument, "ruleset")),
              argExternalConfig = getUrlArg(argument, "config");
  std::string argDeviceID = getUrlArg(argument, "dev_id"),
              argFilename = getUrlArg(argument, "filename"),
              argUpdateInterval = getUrlArg(argument, "interval"),
              argUpdateStrict = getUrlArg(argument, "strict");
  std::string argRenames = getUrlArg(argument, "rename"),
              argFilterScript = getUrlArg(argument, "filter_script"),
              argProviderHeaders = getUrlArg(argument, "provider_headers");

  /// switches with default value
  tribool argUpload = getUrlArg(argument, "upload"),
          argEmoji = getUrlArg(argument, "emoji"),
          argAddEmoji = getUrlArg(argument, "add_emoji"),
          argRemoveEmoji = getUrlArg(argument, "remove_emoji");
  tribool argAppendType = getUrlArg(argument, "append_type"),
          argTFO = getUrlArg(argument, "tfo"),
          argUDP = getUrlArg(argument, "udp"),
          argGenNodeList = getUrlArg(argument, "list");
  tribool argSort = getUrlArg(argument, "sort"),
          argUseSortScript = getUrlArg(argument, "sort_script");
  tribool argGenClashScript = getUrlArg(argument, "script"),
          argEnableInsert = getUrlArg(argument, "insert");
  tribool argSkipCertVerify = getUrlArg(argument, "scv"),
          argFilterDeprecated = getUrlArg(argument, "fdn"),
          argExpandRulesets = getUrlArg(argument, "expand"),
          argAppendUserinfo = getUrlArg(argument, "append_info");
  tribool argPrependInsert = getUrlArg(argument, "prepend"),
          argGenClassicalRuleProvider = getUrlArg(argument, "classic"),
          argTLS13 = getUrlArg(argument, "tls13"),
          argProviderProxyDirect = getUrlArg(argument, "provider_proxy_direct");
  explain.upload_requested = argUpload.get(false);
  if (explainMode && argUpload) {
    argUpload = false;
    explain.upload_suppressed = true;
  }

  std::string base_content, output_content;
  ProxyGroupConfigs lCustomProxyGroups = global.customProxyGroups;
  RulesetConfigs lCustomRulesets = global.customRulesets;
  string_array lIncludeRemarks = global.includeRemarks,
               lExcludeRemarks = global.excludeRemarks;
  std::vector<RulesetContent> lRulesetContent;
  extra_settings ext;
  ext.rule_stats = rule_stats;
  std::string subInfo, dummy;
  int interval = !argUpdateInterval.empty()
                     ? to_int(argUpdateInterval, global.updateInterval)
                     : global.updateInterval;
  // Token authentication is permanently disabled for security
  bool authorized = false, strict = !argUpdateStrict.empty()
                                        ? argUpdateStrict == "true"
                                        : global.updateStrict;
  explain.simple_subscription = lSimpleSubscription;

  if (std::find(gRegexBlacklist.cbegin(), gRegexBlacklist.cend(),
                parsed.include_remark) != gRegexBlacklist.cend() ||
      std::find(gRegexBlacklist.cbegin(), gRegexBlacklist.cend(),
                parsed.exclude_remark) != gRegexBlacklist.cend()) {
    response.status_code = 400;
    return "Invalid request: include or exclude filter is not allowed.\n"
           "无效请求：include 或 exclude 过滤条件不被允许。\n"
           "Please remove blocked filter patterns and try again.\n"
           "请移除被拦截的过滤表达式后重试。";
  }

  policy.clash_base = settings.clashBase;
  policy.surge_base = settings.surgeBase;
  policy.mellow_base = settings.mellowBase;
  policy.surfboard_base = settings.surfboardBase;
  policy.stash_base = settings.stashBase;
  policy.quan_base = settings.quanBase;
  policy.quanx_base = settings.quanXBase;
  policy.loon_base = settings.loonBase;
  policy.sssub_base = settings.SSSubBase;
  policy.singbox_base = settings.singBoxBase;

  parsed.enable_insert.define(settings.enableInsert);
  if ((parsed.url.empty() &&
       !(!settings.insertUrls.empty() && parsed.enable_insert)) ||
      parsed.target.empty()) {
    response.status_code = 400;
    return "Invalid request: missing required target or url parameter.\n"
           "无效请求：缺少必需的 target 或 url 参数。\n"
           "Please provide target and url; url may be omitted only when "
           "configured insert nodes are enabled.\n"
           "请提供 target 和 url；只有启用已配置的插入节点时才能省略 url。";
  }

  std::map<std::string, std::string> provider_headers;
  std::string provider_headers_error;
  if (!argProviderHeaders.empty() && argTarget != "clash") {
    *status_code = 400;
    return "Invalid request: provider_headers is supported only for target=clash.\n"
           "无效请求：provider_headers 仅支持 target=clash。";
  }
  if (!providerHeadersFromRequest(request, argProviderHeaders,
                                  provider_headers,
                                  provider_headers_error)) {
    *status_code = 400;
    return "Invalid request: " + provider_headers_error + ".\n"
           "无效请求：proxy-provider 请求头选择失败。";
  }

  /// load request arguments as template variables
  //    string_array req_args = split(argument, "&");
  //    string_map req_arg_map;
  //    for(std::string &x : req_args)
  //    {
  //        string_size pos = x.find("=");
  //        if(pos == x.npos)
  //        {
  //            req_arg_map[x] = "";
  //            continue;
  //        }
  //        if(x.substr(0, pos) == "token")
  //            continue;
  //        req_arg_map[x.substr(0, pos)] = x.substr(pos + 1);
  //    }
  string_map req_arg_map;
  for (auto &x : argument) {
    if (x.first == "token")
      continue;
    req_arg_map[x.first] = x.second;
  }

  /// save template variables
  template_args tpl_args;
  tpl_args.global_vars = global.templateVars;
  tpl_args.request_params = std::move(req_arg_map);

  /// check for proxy settings
  ProxyPolicy proxy = parseProxy(global.proxySubscription);

  /// check other flags
  ext.authorized = authorized;
  ext.append_proxy_type = argAppendType.get(global.appendType);
  // 上游项目默认在 clash 目标下自动把 expand 设为 true
  // 本项目默认 expand=false（使用 rule-provider 模式不展开规则集）
  // 若用户主动传入 expand=true，则按照用户意愿内联展开规则集
  parsed.expand_rulesets.define(false);

  policy.generator.clash_proxies_style = settings.clashProxiesStyle;
  policy.generator.clash_proxy_groups_style = settings.clashProxyGroupsStyle;
  policy.generator.stash_request_tfo = parsed.tfo;
  policy.generator.stash_request_udp = parsed.udp;
  policy.generator.stash_request_tls13 = parsed.tls13;
  policy.generator.tfo.define(parsed.tfo).define(settings.TFOFlag);
  policy.generator.udp.define(parsed.udp).define(settings.UDPFlag);
  policy.generator.skip_cert_verify
      .define(parsed.skip_cert_verify)
      .define(settings.skipCertVerify);
  policy.generator.tls13.define(parsed.tls13).define(settings.TLS13Flag);

  /// read preference from argument, assign global var if not in argument
  ext.tfo.define(argTFO).define(global.TFOFlag);
  ext.udp.define(argUDP).define(global.UDPFlag);
  ext.skip_cert_verify.define(argSkipCertVerify).define(global.skipCertVerify);
  ext.tls13.define(argTLS13).define(global.TLS13Flag);

  ext.sort_flag = argSort.get(global.enableSort);
  argUseSortScript.define(!global.sortScript.empty());
  if (ext.sort_flag && argUseSortScript)
    ext.sort_script = global.sortScript;
  ext.filter_deprecated = argFilterDeprecated.get(global.filterDeprecated);
  ext.clash_new_field_name = argClashNewField.get(global.clashUseNewField);
  ext.clash_script = argGenClashScript.get();
  ext.clash_classical_ruleset = argGenClassicalRuleProvider.get();
  ext.custom_openclash_rules_fallback =
      global.customOpenClashRulesFallback;
  ext.custom_openclash_rules_base_url = global.managedConfigPrefix;
  ext.provider_proxy_direct = argProviderProxyDirect.get(true);
  // 无论 expand 取何值，均强制使用 Mihomo 新字段名（proxy-groups / rules）
  // 避免因全局配置为旧字段名而导致 Mihomo 无法识别
  ext.clash_new_field_name = true;
  if (argExpandRulesets)
    ext.clash_script = false;
  explain.expand_rulesets = argExpandRulesets.get(false);

  // Clash defaults to proxy-provider mode, while an explicit list=true keeps
  // the traditional expanded-node behavior.
  ext.nodelist = argGenNodeList.get(false);
  explain.nodelist = ext.nodelist;
  ext.surge_ssr_path = global.surgeSSRPath;
  ext.quanx_dev_id = !argDeviceID.empty() ? argDeviceID : global.quanXDevID;
  ext.enable_rule_generator = global.enableRuleGen;
  ext.overwrite_original_rules = global.overwriteOriginalRules;
  if (!argExpandRulesets)
    ext.managed_config_prefix = global.managedConfigPrefix;
  explain.rule_generator_enabled = ext.enable_rule_generator;
  explain.managed_config = !ext.managed_config_prefix.empty();

  /// load external configuration
  bool userProvidedExternalConfig = !argExternalConfig.empty();
  FetchContext externalConfigContext =
      userProvidedExternalConfig ? FetchContext::PublicRequest
                                 : FetchContext::TrustedConfig;
  FetchContext rulesetFetchContext = FetchContext::TrustedConfig;
  bool configLoadSuccess = false;
  string_map tpl_args_base = tpl_args.local_vars;
  explain.external_config_provided = userProvidedExternalConfig;

  struct ExternalConfigCandidate {
    std::string path;
    FetchContext context;
    bool fallback = false;
  };
  std::vector<ExternalConfigCandidate> config_candidates;
  if (plan.user_provided_external_config) {
    config_candidates.push_back(
        {parsed.external_config, FetchContext::PublicRequest, false});
    if (settings.fallbackToDefaultExternalConfig &&
        !settings.defaultExtConfig.empty() &&
        settings.defaultExtConfig != parsed.external_config) {
      config_candidates.push_back(
          {settings.defaultExtConfig, FetchContext::TrustedConfig, true});
    }
  } else if (!settings.defaultExtConfig.empty()) {
    config_candidates.push_back(
        {settings.defaultExtConfig, FetchContext::TrustedConfig, false});
  }

  if (!argExternalConfig.empty()) {
    // std::cerr<<"External configuration file provided. Loading...\n";
    writeLog(0, "已提供外部配置文件，正在加载...",
             LOG_LEVEL_INFO);
    ExternalConfig extconf;
    extconf.tpl_args = &tpl_args;
    int load_result =
        loadExternalConfig(argExternalConfig, extconf, externalConfigContext);
    if (load_result == 0 &&
        hasEffectiveExternalConfig(extconf, tpl_args, tpl_args_base)) {
      configLoadSuccess = true;
      explain.external_config_loaded = true;
      if (!ext.nodelist) {
        if (checkExternalBase(extconf.sssub_rule_base, lSSSubBase,
                              externalConfigContext))
          baseFetchContext = externalConfigContext;
        if (!lSimpleSubscription) {
          if (checkExternalBase(extconf.clash_rule_base, lClashBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.surge_rule_base, lSurgeBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.surfboard_rule_base, lSurfboardBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.mellow_rule_base, lMellowBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.quan_rule_base, lQuanBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.quanx_rule_base, lQuanXBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.loon_rule_base, lLoonBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;
          if (checkExternalBase(extconf.singbox_rule_base, lSingBoxBase,
                                externalConfigContext))
            baseFetchContext = externalConfigContext;

  auto applyExternalConfig = [&](const ExternalConfig &extconf,
                                 FetchContext context) {
    const bool requested_config = context == FetchContext::PublicRequest;
    rulePrependSources = extconf.rule_prepend_sources;
    ruleAppendSources = extconf.rule_append_sources;
    externalRuleFetchContext = extconf.rule_sources_context;
    if (!policy.generator.nodelist) {
      if (checkExternalBase(extconf.sssub_rule_base, policy.sssub_base,
                            context))
        plan.base_fetch_context = context;
      if (!parsed.simple_subscription) {
        if (checkExternalBase(extconf.clash_rule_base, policy.clash_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.surge_rule_base, policy.surge_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.surfboard_rule_base,
                              policy.surfboard_base, context))
          plan.base_fetch_context = context;
        if (parsed.target == "stash" &&
            checkExternalBase(extconf.stash_rule_base, policy.stash_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.mellow_rule_base, policy.mellow_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.quan_rule_base, policy.quan_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.quanx_rule_base, policy.quanx_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.loon_rule_base, policy.loon_base,
                              context))
          plan.base_fetch_context = context;
        if (checkExternalBase(extconf.singbox_rule_base, policy.singbox_base,
                              context))
          plan.base_fetch_context = context;

        if (!extconf.surge_ruleset.empty()) {
          policy.custom_rulesets = extconf.surge_ruleset;
          rulesetFetchContext = context;
        }
      }
      if (!extconf.rename.empty()) {
        ext.rename_array = extconf.rename;
        ext.rename_for_providers = true;
      }
      if (!extconf.emoji.empty())
        ext.emoji_array = extconf.emoji;
      if (!extconf.include.empty())
        lIncludeRemarks = extconf.include;
      if (!extconf.exclude.empty())
        lExcludeRemarks = extconf.exclude;
      argAddEmoji.define(extconf.add_emoji);
      argRemoveEmoji.define(extconf.remove_old_emoji);
    } else {
      tpl_args.local_vars = tpl_args_base;
      if (load_result == 0) {
        writeLog(
            0,
            "外部配置已加载，但未包含有效设置，按加载失败处理。",
            LOG_LEVEL_WARNING);
      }
    }
    if (!extconf.rename.empty()) {
      policy.generator.rename_array = extconf.rename;
      policy.generator.rename_for_providers = true;
      if (requested_config)
        policy.requested_remote_node_rename = true;
    }
    if (!extconf.emoji.empty())
      policy.generator.emoji_array = extconf.emoji;
    if (!extconf.include.empty()) {
      policy.include_remarks = extconf.include;
      if (requested_config)
        policy.requested_remote_node_filter = true;
    }
    if (!extconf.exclude.empty()) {
      policy.exclude_remarks = extconf.exclude;
      if (requested_config)
        policy.requested_remote_node_filter = true;
    }
    if (requested_config &&
        (extconf.add_emoji.get(false) ||
         extconf.remove_old_emoji.get(false)))
      policy.requested_remote_node_transform = true;
    parsed.add_emoji.define(extconf.add_emoji);
    parsed.remove_emoji.define(extconf.remove_old_emoji);
  };

    bool legacyRemoteFallback =
        userProvidedExternalConfig && !global.defaultExtConfig.empty() &&
        argExternalConfig != global.defaultExtConfig;
    std::vector<std::string> fallbackConfigs =
        buildExternalConfigFallbacks(
            argExternalConfig, global.customOpenClashRulesFallback,
            legacyRemoteFallback);

    if (!configLoadSuccess && !fallbackConfigs.empty()) {
      writeLog(
          0, global.customOpenClashRulesFallback
                 ? "加载外部配置失败，正在尝试远程及内置回退配置..."
                 : "加载用户提供的配置失败，正在尝试默认远程配置...",
          LOG_LEVEL_WARNING);

      for (std::string fallbackConfig : fallbackConfigs) {
        writeLog(0, "正在尝试加载配置：" + fallbackConfig,
                 LOG_LEVEL_INFO);

        tpl_args.local_vars = tpl_args_base;
        ExternalConfig extconf;
        extconf.tpl_args = &tpl_args;
        int fallback_result =
            loadExternalConfig(fallbackConfig, extconf,
                               FetchContext::TrustedConfig);
        if (fallback_result == 0 &&
            hasEffectiveExternalConfig(extconf, tpl_args, tpl_args_base)) {
          writeLog(0, "已成功加载配置：" + fallbackConfig,
                   LOG_LEVEL_INFO);
          configLoadSuccess = true;
          explain.external_config_loaded = true;
          explain.fallback_config_used = true;
          if (!ext.nodelist) {
            checkExternalBase(extconf.sssub_rule_base, lSSSubBase,
                              FetchContext::TrustedConfig);
            if (!lSimpleSubscription) {
              checkExternalBase(extconf.clash_rule_base, lClashBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.surge_rule_base, lSurgeBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.surfboard_rule_base, lSurfboardBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.mellow_rule_base, lMellowBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.quan_rule_base, lQuanBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.quanx_rule_base, lQuanXBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.loon_rule_base, lLoonBase,
                                FetchContext::TrustedConfig);
              checkExternalBase(extconf.singbox_rule_base, lSingBoxBase,
                                FetchContext::TrustedConfig);

              if (!extconf.surge_ruleset.empty())
                lCustomRulesets = extconf.surge_ruleset;
              if (!extconf.custom_proxy_group.empty())
                lCustomProxyGroups = extconf.custom_proxy_group;
              ext.enable_rule_generator = extconf.enable_rule_generator;
              ext.overwrite_original_rules = extconf.overwrite_original_rules;
            }
          }
          if (!extconf.rename.empty()) {
            ext.rename_array = extconf.rename;
            ext.rename_for_providers = true;
          }
          if (!extconf.emoji.empty())
            ext.emoji_array = extconf.emoji;
          if (!extconf.include.empty())
            lIncludeRemarks = extconf.include;
          if (!extconf.exclude.empty())
            lExcludeRemarks = extconf.exclude;
          argAddEmoji.define(extconf.add_emoji);
          argRemoveEmoji.define(extconf.remove_old_emoji);
          break; // Success, stop trying other configs
        } else {
          tpl_args.local_vars = tpl_args_base;
          if (fallback_result == 0) {
            writeLog(
                0,
                "已从 " + fallbackConfig +
                    " 加载配置，但未发现有效设置，跳过。",
                LOG_LEVEL_WARNING);
          } else {
            writeLog(0, "加载配置失败：" + fallbackConfig,
                     LOG_LEVEL_WARNING);
          }
        }
      }

      if (!configLoadSuccess) {
        writeLog(0,
                 global.customOpenClashRulesFallback
                     ? "所有远程及内置回退配置均加载失败。"
                     : "所有默认远程回退配置均加载失败。",
                 LOG_LEVEL_ERROR);
      }
    }
  }

  if (!configLoadSuccess) {
    policy.template_arguments.local_vars = tpl_args_base;
    response.status_code = plan.user_provided_external_config ? 400 : 500;
    response.content_type = "text/plain; charset=utf-8";
    response.headers["Cache-Control"] = "private, no-store";
    if (plan.user_provided_external_config)
      return "Invalid request: selected external configuration could not be "
             "loaded or applied.\n"
             "无效请求：无法加载或应用用户选择的外部配置。";
    return "Server configuration error: default external configuration could "
           "not be loaded or applied.\n"
           "服务器配置错误：无法加载或应用默认外部配置。";
  }

  const size_t externalRuleSourceCount =
      rulePrependSources.size() + ruleAppendSources.size();
  if (externalRuleSourceCount) {
    if (settings.maxAllowedRulesets &&
        externalRuleSourceCount > settings.maxAllowedRulesets) {
      response.status_code = 400;
      return "Invalid request: ruleprepend and ruleappend contain more "
             "sources than max_allowed_rulesets (" +
             std::to_string(settings.maxAllowedRulesets) +
             ").\n"
             "无效请求：ruleprepend 与 ruleappend 的来源总数超过 "
             "max_allowed_rulesets 限制（" +
             std::to_string(settings.maxAllowedRulesets) + "）。";
    }
    if (parsed.target != "clash") {
      response.status_code = 400;
      return "Invalid request: ruleprepend and ruleappend are supported only "
             "for target=clash.\n"
             "无效请求：ruleprepend 与 ruleappend 第一版仅支持 "
             "target=clash。";
    }
    if (parsed.generate_node_list.get(false)) {
      response.status_code = 400;
      return "Invalid request: ruleprepend and ruleappend do not support "
             "list=true.\n"
             "无效请求：ruleprepend 与 ruleappend 不支持 list=true。";
    }
    if (parsed.generate_clash_script.get(false)) {
      response.status_code = 400;
      return "Invalid request: ruleprepend and ruleappend do not support "
             "script=true.\n"
             "无效请求：ruleprepend 与 ruleappend 不支持 script=true。";
    }

    if (!dependency_resolution) {
      std::string external_rule_error;
      if (!fetchExternalRuleSources(rulePrependSources, "ruleprepend",
                                    externalRuleFetchContext,
                                    policy.generator.rule_prepend,
                                    external_rule_error) ||
          !fetchExternalRuleSources(ruleAppendSources, "ruleappend",
                                    externalRuleFetchContext,
                                    policy.generator.rule_append,
                                    external_rule_error)) {
        response.status_code = 400;
        return external_rule_error;
      }
    } else {
      const ProxyPolicy ruleset_proxy =
          parseProxy(settings.proxyRuleset, settings.proxyBypass);
      const string_icase_map no_cache_headers = {
          {"Cache-Control", "no-cache, no-store, max-age=0"},
          {"Pragma", "no-cache"}};
      auto resolve_external_rules = [&](const string_array &sources,
                                        ConversionResourceKind kind,
                                        const std::string &field_name,
                                        string_array &destination)
          -> std::string {
        for (size_t index = 0; index < sources.size(); ++index) {
          const std::string source_identifier =
              field_name + " source #" + std::to_string(index + 1);
          const std::string lower_source = toLower(sources[index]);
          if (!startsWith(lower_source, "http://") &&
              !startsWith(lower_source, "https://")) {
            return "Invalid external rule source " + source_identifier +
                   ": only remote HTTP(S) URLs are supported; local paths "
                   "and data URLs are not allowed.\n外部规则来源 " +
                   source_identifier +
                   " 无效：仅支持远程 HTTP(S) URL，不允许本地路径或 data "
                   "URL。";
          }
          AsyncConversionResourceRequest request;
          request.kind = kind;
          request.source_index = index;
          request.url = sources[index];
          request.proxy = ruleset_proxy;
          request.request_headers = no_cache_headers;
          request.cache_ttl = 0;
          request.context = externalRuleFetchContext;
          const ResolvedConversionResource *resource =
              resolveOrPlanDependency(dependency_resolution,
                                      std::move(request));
          if (!resource)
            continue;
          if (!resource->payload ||
              resource->failure != AsyncFetchFailure::None ||
              resource->payload->status_code < 200 ||
              resource->payload->status_code >= 300 ||
              resource->payload->content.empty()) {
            writeLog(LOG_LEVEL_WARNING,
                     "外部规则来源 " + source_identifier +
                         " 拉取失败、HTTP 状态异常或内容为空，已跳过。");
            continue;
          }
          ExternalRuleParseResult parsed_rules = parseExternalClashRules(
              resource->payload->content, source_identifier,
              ClashRuleTypes);
          if (!parsed_rules.ok)
            return std::move(parsed_rules.error);
          if (parsed_rules.rules.empty())
            return "Invalid external rule source " + source_identifier +
                   ": no usable rules were found.\n外部规则来源 " +
                   source_identifier + " 无效：未找到可用规则。";
          destination.insert(
              destination.end(),
              std::make_move_iterator(parsed_rules.rules.begin()),
              std::make_move_iterator(parsed_rules.rules.end()));
        }
        return {};
      };
      std::string external_rule_error = resolve_external_rules(
          rulePrependSources, ConversionResourceKind::RulePrepend,
          "ruleprepend", policy.generator.rule_prepend);
      if (external_rule_error.empty())
        external_rule_error = resolve_external_rules(
            ruleAppendSources, ConversionResourceKind::RuleAppend,
            "ruleappend", policy.generator.rule_append);
      if (!external_rule_error.empty()) {
        response.status_code = 400;
        return external_rule_error;
      }
    }
  }
  if (ext.enable_rule_generator && !ext.nodelist && !lSimpleSubscription) {
    if (lCustomRulesets != global.customRulesets)
      refreshRulesets(lCustomRulesets, lRulesetContent, rulesetFetchContext);
    else {
      if (global.updateRulesetOnRequest)
        refreshRulesets(lCustomRulesets, lRulesetContent,
                        rulesetFetchContext);
      else
        lRulesetContent = global.rulesetsContent;
    }
  }
  explain.rule_generator_enabled = ext.enable_rule_generator;
  explain.base_fetch_context = fetchContextName(baseFetchContext);
  explain.ruleset_fetch_context = fetchContextName(rulesetFetchContext);
  explain.ruleset_count = lRulesetContent.size();
  explain.custom_group_count = lCustomProxyGroups.size();

  if (dependency_resolution) {
    const std::string *base = selectedTargetBase(parsed, policy);
    plan.base_path = base ? *base : std::string();
    plan.resolved_base_content.clear();
    if (base && !base->empty()) {
      AsyncConversionResourceRequest request;
      request.kind = ConversionResourceKind::Base;
      request.source_index = 0;
      request.url = *base;
      request.proxy = parseProxy(settings.proxyConfig, settings.proxyBypass);
      request.cache_ttl =
          static_cast<unsigned int>(std::max(0, settings.cacheConfig));
      request.context = plan.base_fetch_context;
      const ResolvedConversionResource *resource =
          resolveOrPlanDependency(dependency_resolution,
                                  std::move(request));
      if (resource && resource->payload &&
          resource->failure == AsyncFetchFailure::None)
        plan.resolved_base_content = resource->payload->content;
    }
  }
  parsed.explain.rule_generator_enabled =
      policy.generator.enable_rule_generator;
  parsed.explain.base_fetch_context =
      fetchContextName(plan.base_fetch_context);
  parsed.explain.ruleset_fetch_context =
      fetchContextName(rulesetFetchContext);
  parsed.explain.ruleset_count = plan.ruleset_content.size();
  parsed.explain.custom_group_count = policy.custom_proxy_groups.size();

  if (!parsed.emoji.is_undef()) {
    parsed.add_emoji.set(parsed.emoji);
    parsed.remove_emoji.set(true);
  }
  policy.generator.add_emoji = parsed.add_emoji.get(settings.addEmoji);
  policy.generator.remove_emoji =
      parsed.remove_emoji.get(settings.removeEmoji);
  if (policy.generator.add_emoji && policy.generator.emoji_array.empty())
    policy.generator.emoji_array = settings.emojis;
  if (!parsed.renames.empty()) {
    policy.generator.rename_array =
        INIBinding::from<RegexMatchConfig>::from_ini(
            split(parsed.renames, "`"), "@");
    policy.generator.rename_for_providers = true;
  } else if (policy.generator.rename_array.empty())
    policy.generator.rename_array = settings.renames;

  if (!parsed.include_remark.empty() && regValid(parsed.include_remark))
    policy.include_remarks = string_array{parsed.include_remark};
  if (!parsed.exclude_remark.empty() && regValid(parsed.exclude_remark))
    policy.exclude_remarks = string_array{parsed.exclude_remark};

  return "";
}

struct SubscriptionNodeState {
  std::vector<Proxy> nodes;
  std::string subscription_info;
};

struct SubscriptionResolutionView {
  ResolvedSubscriptionLookup lookup;
  std::vector<UnresolvedSubscriptionSource> *missing = nullptr;
  const string_map *resolved_imports = nullptr;
  std::vector<UnresolvedImportSource> *missing_imports = nullptr;
  bool require_resolved = false;
};

using SubStageResponse = ConversionPipelineStepResult;

static bool parseSourceGroupRule(const std::string &rule,
                                 std::string &source_pattern,
                                 std::string &server_pattern) {
  static const std::string group_regex =
      R"(^!!GROUP=(.+?)(?:!!(.*))?$)";
  if (!startsWith(rule, "!!GROUP="))
    return false;
  source_pattern.clear();
  server_pattern.clear();
  return regGetMatch(rule, group_regex, 3,
                     static_cast<std::string *>(nullptr), &source_pattern,
                     &server_pattern) == 0 &&
         !source_pattern.empty();
}

static bool parseGroupIdRule(const std::string &rule,
                             std::string &group_id_pattern,
                             std::string &server_pattern) {
  static const std::string group_id_regex =
      R"(^!!GROUPID=([\d\-+!,]+)(?:!!(.*))?$)";
  if (!startsWith(rule, "!!GROUPID="))
    return false;
  group_id_pattern.clear();
  server_pattern.clear();
  return regGetMatch(rule, group_id_regex, 3,
                     static_cast<std::string *>(nullptr), &group_id_pattern,
                     &server_pattern) == 0 &&
         !group_id_pattern.empty();
}

static bool remotePolicyRegexIsSafe(const std::string &pattern) {
  return pattern.find(',') == std::string::npos &&
         std::none_of(pattern.begin(), pattern.end(), [](unsigned char ch) {
           return ch < 0x20 || ch == 0x7f;
         });
}

static bool policyPathRegexIsSafe(const std::string &pattern) {
  return pattern.find('"') == std::string::npos &&
         std::none_of(pattern.begin(), pattern.end(), [](unsigned char ch) {
           return ch < 0x20 || ch == 0x7f;
         });
}

static std::string quanxRemoteCapabilityReason(
    const ParsedSubRequest &parsed, const EffectiveSubPolicy &policy,
    const Settings &settings) {
  const extra_settings &ext = policy.generator;
  if (ext.nodelist)
    return "list-mode";
  for (const std::string &raw_item : split(parsed.url, "|")) {
    const TaggedLink tagged = parseTaggedLink(regTrim(raw_item));
    const std::string link = tagged.link.empty() ? raw_item : tagged.link;
    if (startsWith(regTrim(link), "!!import:"))
      return "imported-source-list";
  }
  if (!policy.include_remarks.empty() || !policy.exclude_remarks.empty())
    return "node-filters";
  if (!ext.rename_array.empty())
    return "provider-rename";
  if (!parsed.group_name.empty())
    return "group-override";
  if (ext.add_emoji || ext.remove_emoji || ext.append_proxy_type ||
      ext.sort_flag || ext.filter_deprecated || !settings.filterScript.empty())
    return "node-transform";
  if (!ext.udp.is_undef() || !ext.tfo.is_undef() ||
      !ext.skip_cert_verify.is_undef() || !ext.tls13.is_undef())
    return "node-option-override";

  for (const ProxyGroupConfig &group : policy.custom_proxy_groups) {
    if (group.Type == ProxyGroupType::SSID ||
        group.Type == ProxyGroupType::Relay ||
        group.Type == ProxyGroupType::Smart)
      continue;

    size_t dynamic_rule_count = 0;
    for (const std::string &rule : group.Proxies) {
      if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
        continue;
      if (startsWith(rule, "script:") || startsWith(rule, "!!INSERT=") ||
          startsWith(rule, "!!TYPE=") || startsWith(rule, "!!PORT=") ||
          startsWith(rule, "!!SERVER="))
        return "unsupported-group-selector";

      std::string selector, server_pattern;
      if (parseGroupIdRule(rule, selector, server_pattern) ||
          parseSourceGroupRule(rule, selector, server_pattern)) {
        if (startsWith(rule, "!!GROUP=") && !regValid(selector))
          return "invalid-group-regex";
        if (!server_pattern.empty() &&
            (!remotePolicyRegexIsSafe(server_pattern) ||
             !regValid(server_pattern)))
          return "unsafe-group-regex";
      } else if (startsWith(rule, "!!")) {
        return "unsupported-group-selector";
      } else if (!remotePolicyRegexIsSafe(rule) || !regValid(rule)) {
        return "unsafe-group-regex";
      }

      if (++dynamic_rule_count > 1)
        return "multiple-group-selectors";
    }
    if (!group.UsingProvider.empty() && dynamic_rule_count)
      return "provider-and-rule-selectors";
  }
  return "native-capable";
}

static std::string policyPathCapabilityReason(
    const ParsedSubRequest &parsed, const EffectiveSubPolicy &policy,
    const Settings &settings, RemoteSubscriptionMode mode) {
  const extra_settings &ext = policy.generator;
  const bool surfboard = mode == RemoteSubscriptionMode::SurfboardPolicyPath;
  if ((surfboard && !settings.surfboardPolicyPath) ||
      (!surfboard && !settings.surgePolicyPath))
    return "disabled-by-config";
  if (ext.nodelist)
    return "list-mode";
  if (!surfboard && parsed.surge_version < 3)
    return "unsupported-target-version";

  size_t remote_subscription_count = 0;
  int remote_group_id = -1;
  std::string remote_source_tag;
  std::string remote_requested_name;
  int item_group_id = 0;
  for (const std::string &raw_item : split(parsed.url, "|")) {
    const TaggedLink tagged = parseTaggedLink(regTrim(raw_item));
    const std::string link = tagged.link.empty() ? raw_item : tagged.link;
    if (startsWith(regTrim(link), "!!import:"))
      return "imported-source-list";
    if (surfboard && tagged.has_interval)
      return "unsupported-update-interval";
    if (tagged.error == TaggedLink::Error::None &&
        isHttpSubscriptionLink(
            link, tagged.has_provider || (!surfboard && tagged.has_interval))) {
      remote_subscription_count++;
      remote_group_id = item_group_id;
      remote_source_tag = tagged.tag;
      remote_requested_name = tagged.provider;
    }
    item_group_id++;
  }
  if (remote_subscription_count == 0)
    return "no-remote-subscription";
  if (remote_subscription_count > 1)
    return "multiple-remote-subscriptions";

  if (policy.requested_remote_node_filter)
    return "node-filters";
  if (policy.requested_remote_node_rename)
    return "provider-rename";
  if (!parsed.group_name.empty())
    return "group-override";
  if (policy.requested_remote_node_transform)
    return "node-transform";
  if (policy.requested_remote_node_option_override)
    return "node-option-override";

  bool selects_remote_subscription = false;
  for (const ProxyGroupConfig &group : policy.custom_proxy_groups) {
    size_t dynamic_rule_count = 0;
    for (const std::string &rule : group.Proxies) {
      if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
        continue;
      if (startsWith(rule, "script:") || startsWith(rule, "!!INSERT=") ||
          startsWith(rule, "!!TYPE=") || startsWith(rule, "!!PORT=") ||
          startsWith(rule, "!!SERVER="))
        return "unsupported-group-selector";

      std::string selector, server_pattern;
      const bool group_id_selector =
          parseGroupIdRule(rule, selector, server_pattern);
      const bool source_selector =
          !group_id_selector &&
          parseSourceGroupRule(rule, selector, server_pattern);
      if (group_id_selector || source_selector) {
        if (startsWith(rule, "!!GROUP=") && !regValid(selector))
          return "invalid-group-regex";
        if (!server_pattern.empty() &&
            (!policyPathRegexIsSafe(server_pattern) ||
             !regValid(server_pattern)))
          return "unsafe-group-regex";
      } else if (startsWith(rule, "!!")) {
        return "unsupported-group-selector";
      } else if (!policyPathRegexIsSafe(rule) || !regValid(rule)) {
        return "unsafe-group-regex";
      }

      if (group_id_selector && matchRange(selector, remote_group_id))
        selects_remote_subscription = true;
      else if (source_selector && !remote_source_tag.empty() &&
               regFind(remote_source_tag, selector))
        selects_remote_subscription = true;
      else if (!group_id_selector && !source_selector)
        selects_remote_subscription = true;
      if (++dynamic_rule_count > 1)
        return "multiple-group-selectors";
    }

    if (!group.UsingProvider.empty()) {
      if (dynamic_rule_count)
        return "provider-and-rule-selectors";
      if (!remote_requested_name.empty() &&
          std::find(group.UsingProvider.begin(), group.UsingProvider.end(),
                    remote_requested_name) != group.UsingProvider.end())
        selects_remote_subscription = true;
    }
    if ((group.Type == ProxyGroupType::SSID ||
         group.Type == ProxyGroupType::Relay ||
         group.Type == ProxyGroupType::Smart) &&
        (dynamic_rule_count || !group.UsingProvider.empty()))
      return "unsupported-group-type";
  }

  return selects_remote_subscription ? "native-capable"
                                     : "no-remote-policy-group";
}

struct LoonProspectiveRemote {
  int group_id = 0;
  std::string source_tag;
  std::string requested_name;
  std::string selection_name;
};

static bool loonGroupRuleSelectsRemote(
    const std::string &rule,
    const std::vector<LoonProspectiveRemote> &remotes) {
  std::string selector, server_pattern;
  if (parseGroupIdRule(rule, selector, server_pattern)) {
    return std::any_of(remotes.begin(), remotes.end(), [&](const auto &remote) {
      return matchRange(selector, remote.group_id);
    });
  }
  if (parseSourceGroupRule(rule, selector, server_pattern)) {
    return std::any_of(remotes.begin(), remotes.end(), [&](const auto &remote) {
      return !remote.source_tag.empty() && regFind(remote.source_tag, selector);
    });
  }
  return !startsWith(rule, "!!") && !startsWith(rule, "script:");
}

static std::string loonRemoteCapabilityReason(
    const ParsedSubRequest &parsed, const EffectiveSubPolicy &policy,
    const Settings &settings) {
  if (!settings.loonRemoteProxy)
    return "disabled-by-config";
  if (policy.generator.nodelist)
    return "list-mode";
  std::vector<LoonProspectiveRemote> remotes;
  int item_group_id = 0;
  size_t generated_index = 0;
  for (const std::string &raw_item : split(parsed.url, "|")) {
    const TaggedLink tagged = parseTaggedLink(regTrim(raw_item));
    const std::string link = tagged.link.empty() ? raw_item : tagged.link;
    if (startsWith(regTrim(link), "!!import:"))
      return "imported-source-list";
    if (tagged.has_interval)
      return "unsupported-update-interval";
    if (tagged.error == TaggedLink::Error::None &&
        isHttpSubscriptionLink(link, tagged.has_provider)) {
      std::string selection_name = sanitizeRemoteResourceName(tagged.provider);
      if (selection_name.empty())
        selection_name =
            "SubConverter_Remote_" + std::to_string(++generated_index);
      remotes.push_back({item_group_id, tagged.tag, tagged.provider,
                         std::move(selection_name)});
    }
    item_group_id++;
  }
  if (remotes.empty())
    return "no-remote-subscription";

  if (policy.requested_remote_node_filter)
    return "node-filters";
  if (policy.requested_remote_node_rename)
    return "provider-rename";
  if (!parsed.group_name.empty())
    return "group-override";
  if (policy.requested_remote_node_transform)
    return "node-transform";
  if (policy.requested_remote_node_option_override)
    return "node-option-override";

  bool selects_remote_subscription = false;
  for (const ProxyGroupConfig &group : policy.custom_proxy_groups) {
    bool group_has_dynamic_selector = false;
    for (const std::string &rule : group.Proxies) {
      if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
        continue;
      {
        const std::string normalized_rule = toLower(rule);
        if (startsWith(normalized_rule, "http://") ||
            startsWith(normalized_rule, "https://"))
          continue;
      }
      group_has_dynamic_selector = true;
      if (startsWith(rule, "script:") || startsWith(rule, "!!INSERT=") ||
          startsWith(rule, "!!TYPE=") || startsWith(rule, "!!PORT=") ||
          startsWith(rule, "!!SERVER="))
        return "unsupported-group-selector";

      std::string selector, server_pattern;
      if (parseGroupIdRule(rule, selector, server_pattern) ||
          parseSourceGroupRule(rule, selector, server_pattern)) {
        if (startsWith(rule, "!!GROUP=") && !regValid(selector))
          return "invalid-group-regex";
        if (!server_pattern.empty() &&
            (!policyPathRegexIsSafe(server_pattern) ||
             !regValid(server_pattern)))
          return "unsafe-group-regex";
      } else if (startsWith(rule, "!!")) {
        return "unsupported-group-selector";
      } else if (!policyPathRegexIsSafe(rule) || !regValid(rule)) {
        return "unsafe-group-regex";
      }
      if (loonGroupRuleSelectsRemote(rule, remotes))
        selects_remote_subscription = true;
    }

    for (const std::string &provider : group.UsingProvider) {
      const std::string sanitized = sanitizeRemoteResourceName(provider);
      if (std::any_of(remotes.begin(), remotes.end(), [&](const auto &remote) {
            return provider == remote.requested_name ||
                   provider == remote.selection_name ||
                   sanitized == remote.selection_name;
          }))
        selects_remote_subscription = true;
    }

    if ((group.Type == ProxyGroupType::SSID ||
         group.Type == ProxyGroupType::Relay ||
         group.Type == ProxyGroupType::Smart) &&
        (group_has_dynamic_selector || !group.UsingProvider.empty()))
      return "unsupported-group-type";
  }

  return selects_remote_subscription ? "native-capable"
                                     : "no-remote-policy-group";
}

struct StashProspectiveProvider {
  int group_id = 0;
  std::string source_tag;
  std::string requested_name;
  std::string selection_name;
};

static bool stashGroupRuleSelectsProvider(
    const std::string &rule,
    const std::vector<StashProspectiveProvider> &providers) {
  std::string selector, server_pattern;
  if (parseGroupIdRule(rule, selector, server_pattern)) {
    return std::any_of(providers.begin(), providers.end(),
                       [&](const auto &provider) {
                         return matchRange(selector, provider.group_id);
                       });
  }
  if (parseSourceGroupRule(rule, selector, server_pattern)) {
    return std::any_of(providers.begin(), providers.end(),
                       [&](const auto &provider) {
                         return !provider.source_tag.empty() &&
                                regFind(provider.source_tag, selector);
                       });
  }
  return !startsWith(rule, "!!") && !startsWith(rule, "script:");
}

static std::string stashProxyProviderCapabilityReason(
    const ParsedSubRequest &parsed, const EffectiveSubPolicy &policy) {
  if (policy.generator.nodelist)
    return "list-mode";
  if (parsed.provider_proxy_direct.get(false))
    return "unsupported-provider-proxy";

  std::vector<StashProspectiveProvider> providers;
  std::unordered_set<std::string> reserved_provider_keys;
  int item_group_id = 0;
  size_t generated_index = 0;
  for (const std::string &raw_item : split(parsed.url, "|")) {
    const TaggedLink tagged = parseTaggedLink(regTrim(raw_item));
    const std::string link = tagged.link.empty() ? raw_item : tagged.link;
    if (startsWith(regTrim(link), "!!import:"))
      return "imported-source-list";
    if (tagged.has_proxy_direct)
      return "unsupported-provider-proxy";
    if (tagged.has_interval && tagged.interval <= 0)
      return "invalid-update-interval";
    if (tagged.error == TaggedLink::Error::None &&
        isHttpSubscriptionLink(
            link, tagged.has_provider || tagged.has_interval)) {
      std::string selection_name = sanitizeRemoteResourceName(tagged.provider);
      if (selection_name.empty())
        selection_name =
            "SubConverter_Provider_" + std::to_string(++generated_index);
      selection_name = reserveStashProviderName(selection_name,
                                                reserved_provider_keys);
      providers.push_back({item_group_id, tagged.tag, tagged.provider,
                           std::move(selection_name)});
    }
    item_group_id++;
  }
  if (providers.empty())
    return "no-remote-subscription";

  if (policy.requested_remote_node_filter)
    return "node-filters";
  if (policy.requested_remote_node_rename)
    return "provider-rename";
  if (!parsed.group_name.empty())
    return "group-override";
  if (policy.requested_remote_node_transform)
    return "node-transform";
  if (policy.requested_remote_node_option_override)
    return "node-option-override";

  // The built-in Stash base contains a safe `Proxy` selector. When no custom
  // groups are configured, the generator attaches every provider to that
  // selector so legacy preference files need no migration.
  if (policy.custom_proxy_groups.empty())
    return "native-capable";

  bool selects_remote_provider = false;
  for (const ProxyGroupConfig &group : policy.custom_proxy_groups) {
    if (group.Type == ProxyGroupType::Smart ||
        group.Type == ProxyGroupType::SSID)
      return "unsupported-group-type";
    size_t dynamic_selector_count = 0;
    for (const std::string &rule : group.Proxies) {
      if (startsWith(rule, "[]") || rule == "DIRECT" || rule == "REJECT")
        continue;
      {
        const std::string normalized_rule = toLower(rule);
        if (startsWith(normalized_rule, "http://") ||
            startsWith(normalized_rule, "https://"))
          continue;
      }
      if (startsWith(rule, "script:") || startsWith(rule, "!!INSERT=") ||
          startsWith(rule, "!!TYPE=") || startsWith(rule, "!!PORT=") ||
          startsWith(rule, "!!SERVER="))
        return "unsupported-group-selector";

      std::string selector, server_pattern;
      if (parseGroupIdRule(rule, selector, server_pattern) ||
          parseSourceGroupRule(rule, selector, server_pattern)) {
        if (startsWith(rule, "!!GROUP=") && !regValid(selector))
          return "invalid-group-regex";
        if (!server_pattern.empty() &&
            (!remotePolicyRegexIsSafe(server_pattern) ||
             !regValid(server_pattern)))
          return "unsafe-group-regex";
      } else if (startsWith(rule, "!!")) {
        return "unsupported-group-selector";
      } else if (!remotePolicyRegexIsSafe(rule) || !regValid(rule)) {
        return "unsafe-group-regex";
      }
      if (++dynamic_selector_count > 1)
        return "multiple-group-selectors";
      if (stashGroupRuleSelectsProvider(rule, providers))
        selects_remote_provider = true;
    }

    if (!group.UsingProvider.empty() && dynamic_selector_count)
      return "provider-and-rule-selectors";
    for (const std::string &requested : group.UsingProvider) {
      const std::string sanitized = sanitizeRemoteResourceName(requested);
      if (std::any_of(providers.begin(), providers.end(),
                      [&](const auto &provider) {
                        return requested == provider.requested_name ||
                               requested == provider.selection_name ||
                               sanitized == provider.selection_name;
                      }))
        selects_remote_provider = true;
    }
    if (group.Type == ProxyGroupType::Relay &&
        (dynamic_selector_count || !group.UsingProvider.empty()))
      return "unsupported-group-type";
  }

  return selects_remote_provider ? "native-capable"
                                 : "no-remote-policy-group";
}

static SubStageResponse processSubscriptionNodes(
    Request &request, Response &response, const Settings &settings,
    ParsedSubRequest &parsed, EffectiveSubPolicy &policy,
    SubscriptionNodeState &state,
    const SubscriptionResolutionView *resolution = nullptr) {
  std::optional<ScopedResolvedImportView> import_resolution;
  if (resolution)
    import_resolution.emplace(resolution->resolved_imports,
                              resolution->missing_imports);
  int *status_code = &response.status_code;
  std::string &argTarget = parsed.target;
  std::string &argUrl = parsed.url;
  std::string &argGroupName = parsed.group_name;
  std::string &argProviderHeaders = parsed.provider_headers;
  tribool &argUpload = parsed.upload;
  tribool &argEnableInsert = parsed.enable_insert;
  tribool &argAppendUserinfo = parsed.append_userinfo;
  tribool &argPrependInsert = parsed.prepend_insert;
  SubExplainReport &explain = parsed.explain;
  string_array &lIncludeRemarks = policy.include_remarks;
  string_array &lExcludeRemarks = policy.exclude_remarks;
  std::map<std::string, std::string> &provider_headers =
      policy.provider_headers;
  ProxyPolicy &proxy = policy.subscription_proxy;
  extra_settings &ext = policy.generator;

  RegexMatchConfigs stream_temp = settings.streamNodeRules,
                    time_temp = settings.timeNodeRules;
  string_array urls;
  std::vector<Proxy> &nodes = state.nodes;
  std::vector<Proxy> insert_nodes;
  std::string &subInfo = state.subscription_info;
  int groupID = 0;
  size_t source_calls = 0;
  size_t source_failures = 0;
  NodeParserStats parser_stats;

  RemoteSubscriptionMode remote_mode =
      parsed.target_descriptor->remote_subscription_mode;
  std::string remote_reason = "target-default";
  if (ext.nodelist) {
    remote_mode = RemoteSubscriptionMode::ServerSideParse;
    remote_reason = "list-mode";
  } else if (remote_mode == RemoteSubscriptionMode::QuanXServerRemote) {
    remote_reason = quanxRemoteCapabilityReason(parsed, policy, settings);
    if (remote_reason != "native-capable")
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
  } else if (remote_mode == RemoteSubscriptionMode::SurgePolicyPath) {
    remote_reason =
        policyPathCapabilityReason(parsed, policy, settings, remote_mode);
    if (remote_reason != "native-capable")
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
  } else if (remote_mode == RemoteSubscriptionMode::SurfboardPolicyPath) {
    remote_reason =
        policyPathCapabilityReason(parsed, policy, settings, remote_mode);
    if (remote_reason != "native-capable")
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
  } else if (remote_mode == RemoteSubscriptionMode::LoonRemoteProxy) {
    remote_reason = loonRemoteCapabilityReason(parsed, policy, settings);
    if (remote_reason != "native-capable")
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
  } else if (remote_mode == RemoteSubscriptionMode::StashProxyProvider) {
    remote_reason = stashProxyProviderCapabilityReason(parsed, policy);
    if (remote_reason != "native-capable")
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
  }
  explain.remote_subscription_backend = remoteSubscriptionModeName(remote_mode);
  explain.remote_subscription_reason = remote_reason;

  if (remote_mode == RemoteSubscriptionMode::SurgePolicyPath ||
      remote_mode == RemoteSubscriptionMode::SurfboardPolicyPath ||
      remote_mode == RemoteSubscriptionMode::LoonRemoteProxy ||
      remote_mode == RemoteSubscriptionMode::StashProxyProvider) {
    const size_t configured_filter_count =
        policy.include_remarks.size() + policy.exclude_remarks.size();
    const size_t configured_node_transform_count =
        static_cast<size_t>(policy.generator.add_emoji) +
        static_cast<size_t>(policy.generator.remove_emoji) +
        static_cast<size_t>(policy.generator.append_proxy_type) +
        static_cast<size_t>(policy.generator.sort_flag) +
        static_cast<size_t>(policy.generator.filter_deprecated) +
        static_cast<size_t>(!settings.filterScript.empty());
    const size_t configured_node_option_count =
        static_cast<size_t>(!policy.generator.udp.is_undef()) +
        static_cast<size_t>(!policy.generator.tfo.is_undef()) +
        static_cast<size_t>(
            !policy.generator.skip_cert_verify.is_undef()) +
        static_cast<size_t>(!policy.generator.tls13.is_undef());
    if (configured_filter_count || !policy.generator.rename_array.empty() ||
        configured_node_transform_count || configured_node_option_count) {
      writeLog(
          LOG_LEVEL_INFO,
          std::string(remote_mode == RemoteSubscriptionMode::SurgePolicyPath
                          ? "SURGE_POLICY_PATH"
                          : remote_mode ==
                                    RemoteSubscriptionMode::SurfboardPolicyPath
                                ? "SURFBOARD_POLICY_PATH"
                                : remote_mode ==
                                          RemoteSubscriptionMode::LoonRemoteProxy
                                      ? "LOON_REMOTE"
                                      : "STASH_PROXY_PROVIDER") +
              "_TRANSFORM_SCOPE remote_nodes=client "
          "direct_nodes=server configured_filters=" +
              std::to_string(configured_filter_count) +
              " configured_rename_rules=" +
              std::to_string(policy.generator.rename_array.size()) +
              " configured_node_transforms=" +
              std::to_string(configured_node_transform_count) +
              " configured_node_option_overrides=" +
              std::to_string(configured_node_option_count));
    }
  }

  parse_settings parse_set;
  parse_set.proxy = &proxy;
  parse_set.exclude_remarks = &lExcludeRemarks;
  parse_set.include_remarks = &lIncludeRemarks;
  parse_set.stream_rules = &stream_temp;
  parse_set.time_rules = &time_temp;
  parse_set.sub_info = &subInfo;
  parse_set.authorized = authorized;
  parse_set.mihomo_only = argTarget == "clash" || argTarget == "clashr";
  string_icase_map subscription_headers = buildSubscriptionRequestHeaders();
  std::string selected_user_agent = providerUserAgentFromRequest(request);
  if (!selected_user_agent.empty())
    subscription_headers["User-Agent"] = selected_user_agent;
  for (const auto &[name, value] : provider_headers)
    subscription_headers[name] = value;
  parse_set.request_header = &subscription_headers;
  parse_set.fetch_context = FetchContext::TrustedConfig;
  parse_set.js_runtime = ext.js_runtime;
  parse_set.js_context = ext.js_context;
  if (resolution) {
    parse_set.resolved_subscription_lookup = resolution->lookup;
    parse_set.missing_subscription_sources = resolution->missing;
    parse_set.require_resolved_subscription =
        resolution->require_resolved;
  }

  auto logRouteSelection = [&]() {
    const size_t provider_count = ext.providers.size();
    const size_t remote_count = ext.quanx_server_remotes.size() +
                                ext.surge_policy_paths.size() +
                                ext.surfboard_policy_paths.size() +
                                ext.loon_remote_proxies.size() +
                                ext.stash_proxy_providers.size();
    std::string route = "none";
    if ((provider_count || remote_count) && source_calls)
      route = "hybrid";
    else if (provider_count)
      route = "proxy-provider";
    else if (remote_count)
      route = remoteSubscriptionModeName(remote_mode);
    else if (parser_stats.invocations)
      route = "node-parser";
    else if (source_calls)
      route = "node-source";
    std::string event =
        "SUB_ROUTE_RESULT target=" + parsed.target +
        " source=" +
        std::string(parsed.target_was_auto ? "auto" : "explicit") +
        " route=" + route + " parser_policy=" +
        nodeParserModeName(parse_set.parser_mode) + " parser=" +
        (parser_stats.invocations
             ? std::string(nodeParserModeName(parse_set.parser_mode))
             : std::string("none")) +
        " provider_count=" + std::to_string(provider_count) +
        " source_calls=" + std::to_string(source_calls) +
        " source_failures=" + std::to_string(source_failures) +
        " parser_calls=" + std::to_string(parser_stats.invocations) +
        " parser_failures=" + std::to_string(parser_stats.failures);
    if (parsed.target_descriptor->remote_subscription_mode ==
            RemoteSubscriptionMode::QuanXServerRemote ||
        parsed.target_descriptor->remote_subscription_mode ==
            RemoteSubscriptionMode::SurgePolicyPath ||
        parsed.target_descriptor->remote_subscription_mode ==
            RemoteSubscriptionMode::SurfboardPolicyPath ||
        parsed.target_descriptor->remote_subscription_mode ==
            RemoteSubscriptionMode::LoonRemoteProxy ||
        parsed.target_descriptor->remote_subscription_mode ==
            RemoteSubscriptionMode::StashProxyProvider) {
      event += " remote_backend=" +
               std::string(remoteSubscriptionModeName(remote_mode)) +
               " remote_reason=" + remote_reason +
               " remote_count=" + std::to_string(remote_count);
    }
    writeLog(LOG_LEVEL_INFO, event);
  };

  if (!settings.insertUrls.empty() && argEnableInsert) {
    groupID = -1;
    urls = split(global.insertUrls, "|");
    explain.insert_url_count = urls.size();
    importItems(urls, true);
    for (std::string &x : urls) {
      x = regTrim(x);
      writeLog(0, "正在从 URL 获取节点数据：'" + x + "'。", LOG_LEVEL_INFO);
      if (addNodes(x, insert_nodes, groupID, parse_set) == -1) {
        if (global.skipFailedLinks)
          writeLog(
              0, "以下链接不包含任何有效节点信息：" + x,
              LOG_LEVEL_WARNING);
        else {
          logRouteSelection();
          *status_code = 400;
          return {true,
                  "Invalid request: this link does not contain any supported "
                  "proxy nodes.\n"
                  "无效请求：该链接不包含任何受支持的代理节点。\n"
                  "Please check whether the link is reachable and the node "
                  "URI format is supported.\n"
                  "请检查链接是否可访问，以及节点 URI 格式是否受支持。"};
        }
      }
      groupID--;
    }
  }
  urls = split(argUrl, "|");
  explain.raw_url_count = urls.size();
  parse_set.fetch_context = FetchContext::PublicRequest;
  groupID = 0;

  const bool provider_mode_eligible =
      remote_mode == RemoteSubscriptionMode::ClashProxyProvider;
  const bool quanx_remote_eligible =
      remote_mode == RemoteSubscriptionMode::QuanXServerRemote;
  const bool surge_remote_eligible =
      remote_mode == RemoteSubscriptionMode::SurgePolicyPath;
  const bool surfboard_remote_eligible =
      remote_mode == RemoteSubscriptionMode::SurfboardPolicyPath;
  const bool loon_remote_eligible =
      remote_mode == RemoteSubscriptionMode::LoonRemoteProxy;
  const bool stash_remote_eligible =
      remote_mode == RemoteSubscriptionMode::StashProxyProvider;
  const bool native_remote_target =
      parsed.target_descriptor->remote_subscription_mode ==
          RemoteSubscriptionMode::QuanXServerRemote ||
      parsed.target_descriptor->remote_subscription_mode ==
          RemoteSubscriptionMode::SurgePolicyPath ||
      parsed.target_descriptor->remote_subscription_mode ==
          RemoteSubscriptionMode::SurfboardPolicyPath ||
      parsed.target_descriptor->remote_subscription_mode ==
          RemoteSubscriptionMode::LoonRemoteProxy ||
      parsed.target_descriptor->remote_subscription_mode ==
          RemoteSubscriptionMode::StashProxyProvider;
  if (!provider_mode_eligible && !quanx_remote_eligible &&
      !surge_remote_eligible && !surfboard_remote_eligible &&
      !loon_remote_eligible && !stash_remote_eligible) {
    for (size_t index = 0; index < urls.size(); ++index) {
      TaggedLink tagged = parseTaggedLink(regTrim(urls[index]));
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }
      if (tagged.has_interval) {
        *status_code = 400;
        return {true, providerIntervalScopeError(index)};
      }
      if (tagged.has_proxy_direct) {
        *status_code = 400;
        return {true, providerDirectScopeError(index)};
      }
      if (native_remote_target && tagged.has_provider) {
        std::string normalized = tagged.link;
        if (tagged.has_tag)
          normalized = "tag:" + tagged.tag + "," + normalized;
        urls[index] = std::move(normalized);
      }
    }
  }

  if (provider_mode_eligible) {
    struct SubscriptionLinkItem {
      std::string url;
      std::string tag;
      std::string provider;
      int interval = 0;
      bool proxy_direct = kDefaultProxyProviderDirect;
      bool has_interval = false;
      bool has_proxy_direct = false;
      bool url_decoded = false;
    };
    std::vector<SubscriptionLinkItem> subscription_urls;
    std::vector<std::string> node_urls;

    for (size_t index = 0; index < urls.size(); ++index) {
      std::string &x = urls[index];
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }
      std::string link = tagged.link.empty() ? x : tagged.link;

      // Keep HTTP(S)/data links available for proxy-provider mode. Other
      // Mihomo-supported schemes are direct node links.
      bool isNodeLink = mihomo::isSupportedNonHttpSchemeLink(link);

      if (isNodeLink) {
        if (tagged.has_interval) {
          *status_code = 400;
          return {true, providerIntervalScopeError(index)};
        }
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        std::string node_link = tagged.has_node ? "node:" + link : link;
        if (tagged.has_tag)
          node_link = "tag:" + tagged.tag + "," + link;
        writeLog(0, "检测到节点链接：'" + link + "'，将直接解析。",
                 LOG_LEVEL_INFO);
        node_urls.push_back(node_link);
        explain.node_link_count++;
      } else if (isLink(link) || mihomo::isHttpSchemeLink(link)) {
        // HTTP/HTTPS 订阅链接
        writeLog(
            0, "检测到订阅链接：'" + link + "'，将创建 provider。",
            LOG_LEVEL_INFO);
        subscription_urls.push_back(
            {link, tagged.tag, tagged.provider, tagged.link_decoded});
        explain.subscription_url_count++;
      } else {
        if (tagged.has_interval) {
          *status_code = 400;
          return {true, providerIntervalScopeError(index)};
        }
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        std::string node_link = link;
        if (tagged.has_tag)
          node_link = "tag:" + tagged.tag + "," + link;
        writeLog(0, "未知 URL 类型：'" + link + "'，按节点链接处理。",
                 LOG_LEVEL_WARNING);
        node_urls.push_back(node_link);
        explain.node_link_count++;
        explain.unknown_node_link_count++;
      }
    }

    if (!subscription_urls.empty()) {
      writeLog(0, "检测到订阅 URL，启用 proxy-provider 模式。",
               LOG_LEVEL_INFO);
      ext.use_proxy_provider = true;
      std::string provider_user_agent =
          argTarget == "clash" ? providerUserAgentFromRequest(request) : "";
      std::unordered_set<std::string> provider_names;
      auto reserve_provider_name = [&](const std::string &base) {
        std::string base_name =
            clampProviderNameLength(base, kProviderNameMaxLen);
        base_name = trimOf(base_name, '.', true, true);
        if (base_name.empty())
          base_name = "Provider";
        if (provider_names.insert(base_name).second)
          return base_name;
        int index = 1;
        while (true) {
          std::string suffix = "_" + std::to_string(index);
          size_t max_base = kProviderNameMaxLen > suffix.size()
                                ? kProviderNameMaxLen - suffix.size()
                                : 0;
          std::string prefix = clampProviderNameLength(base_name, max_base);
          prefix = trimOf(prefix, '.', true, true);
          if (prefix.empty())
            prefix = clampProviderNameLength("Provider", max_base);
          std::string candidate = prefix + suffix;
          if (provider_names.insert(candidate).second)
            return candidate;
          index++;
        }
      };

      size_t generated_explain_provider_index = 0;

      for (const SubscriptionLinkItem &item : subscription_urls) {
        ProxyProvider provider;
        std::string urlHash =
            item.url_decoded ? generateProviderHashFromDecodedUrl(item.url)
                             : generateProviderHash(item.url);
        std::string default_name = "Provider_" + urlHash;
        std::string sanitized_provider = sanitizeProviderName(item.provider);
        const bool generated_provider_name = sanitized_provider.empty();
        std::string base_name =
            sanitized_provider.empty() ? default_name : sanitized_provider;
        base_name = sanitizeProviderName(base_name);
        if (base_name.empty())
          base_name = default_name;
        provider.name = reserve_provider_name(base_name);
        provider.tag = item.tag;
        writeLog(0,
                 "已生成 provider：" + provider.name + "，URL：" +
                     item.url,
                 LOG_LEVEL_INFO);
        provider.url = item.url_decoded ? item.url
                                        : urlDecode(item.url); // 解码 URL
        provider.interval = 0;    // 禁止自动周期更新订阅
        provider.groupId = groupID;
        provider.path = "./providers/" + provider.name + ".yaml";
        provider.user_agent = provider_user_agent;
        provider.headers = provider_headers;

        // Provider mode cannot filter expanded nodes locally, so pass the
        // final effective remark filters through to Mihomo.
        provider.filter = buildProviderRemarkFilter(lIncludeRemarks);
        provider.exclude_filter =
            buildProviderRemarkFilter(lExcludeRemarks);

        ext.providers.push_back(provider);
        SubExplainProvider explain_provider;
        explain_provider.name = provider.name;
        explain_provider.tag = provider.tag;
        explain_provider.source_hash = shortHash(provider.url);
        explain_provider.path = provider.path;
        explain_provider.filter = provider.filter;
        explain_provider.exclude_filter = provider.exclude_filter;
        explain_provider.group_id = provider.groupId;
        explain_provider.interval = provider.interval;
        explain.providers.push_back(std::move(explain_provider));
        groupID++;
      }
    } else {
      // 没有订阅链接，禁用 proxy-provider 模式
      writeLog(0, "未检测到订阅 URL，禁用 proxy-provider 模式。",
               LOG_LEVEL_INFO);
      ext.use_proxy_provider = false;
    }

    if (!node_urls.empty()) {
      writeLog(0,
               "正在直接解析 " + std::to_string(node_urls.size()) +
                   " 个节点链接。",
               LOG_LEVEL_INFO);
      importItems(node_urls, true, FetchContext::PublicRequest);
      for (std::string &x : node_urls) {
        writeLog(0, "正在从 URL 获取节点数据：'" + x + "'。", LOG_LEVEL_INFO);
        if (addNodes(x, nodes, groupID, parse_set) == -1) {
          // 跳过无法解析的节点链接，记录警告后继续处理其他节点
          writeLog(0,
                   "已跳过无效节点链接：'" + x + "'，继续处理其他节点。",
                   LOG_LEVEL_WARNING);
        }
        groupID++;
      }
    }
  } else if (quanx_remote_eligible) {
    struct QuanXRemoteLinkItem {
      std::string url;
      std::string source_tag;
      std::string resource_tag;
      int interval = 0;
      bool has_interval = false;
      int group_id = 0;
    };
    struct QuanXNodeLinkItem {
      std::string url;
      int group_id = 0;
      bool force_direct_link = false;
    };
    std::vector<QuanXRemoteLinkItem> subscription_urls;
    std::vector<QuanXNodeLinkItem> node_urls;

    for (size_t index = 0; index < urls.size(); ++index) {
      std::string &x = urls[index];
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }
      std::string link = tagged.link.empty() ? x : tagged.link;
      const bool is_remote_subscription = isHttpSubscriptionLink(
          link, tagged.has_provider || tagged.has_interval);
      const int item_group_id = groupID++;

      if (is_remote_subscription) {
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        const std::string decoded_link = link;
        if (hasUnsafeQuanXRemoteUrlChar(decoded_link)) {
          *status_code = 400;
          return {true, quanxRemoteSourceError(index)};
        }
        writeLog(LOG_LEVEL_INFO,
                 "检测到 Quantumult X 远程订阅：" +
                     summarizeUrlForLog(decoded_link) +
                     "，将由客户端更新。");
        subscription_urls.push_back(
            {decoded_link, tagged.tag, tagged.provider, tagged.interval,
             tagged.has_interval, item_group_id});
        explain.subscription_url_count++;
        continue;
      }

      if (tagged.has_interval) {
        *status_code = 400;
        return {true, providerIntervalScopeError(index)};
      }
      if (tagged.has_proxy_direct) {
        *status_code = 400;
        return {true, providerDirectScopeError(index)};
      }
      std::string node_link = link;
      if (tagged.has_tag)
        node_link = "tag:" + tagged.tag + "," + link;
      node_urls.push_back(
          {std::move(node_link), item_group_id, isLegacyHttpProxyUri(link)});
      explain.node_link_count++;
    }

    std::unordered_set<std::string> resource_tags;
    auto reserve_resource_tag = [&](const std::string &base) {
      std::string base_tag =
          clampProviderNameLength(base, kProviderNameMaxLen);
      if (base_tag.empty())
        base_tag = "Provider";
      if (resource_tags.insert(base_tag).second)
        return base_tag;
      int suffix_index = 1;
      while (true) {
        const std::string suffix = "_" + std::to_string(suffix_index++);
        const size_t max_base = kProviderNameMaxLen > suffix.size()
                                    ? kProviderNameMaxLen - suffix.size()
                                    : 0;
        std::string candidate =
            clampProviderNameLength(base_tag, max_base) + suffix;
        if (resource_tags.insert(candidate).second)
          return candidate;
      }
    };

    for (const QuanXRemoteLinkItem &item : subscription_urls) {
      const std::string default_tag =
          "Provider_" + generateProviderHashFromDecodedUrl(item.url);
      std::string requested_tag = sanitizeRemoteResourceName(item.resource_tag);
      if (requested_tag.empty())
        requested_tag = default_tag;

      QuanXServerRemote remote;
      remote.resource_tag = reserve_resource_tag(requested_tag);
      remote.requested_resource_tag = item.resource_tag;
      remote.selection_resource_tag = remote.resource_tag;
      remote.source_tag = item.source_tag;
      remote.url = item.url;
      remote.update_interval = item.interval;
      remote.has_update_interval = item.has_interval;
      remote.group_id = item.group_id;
      writeLog(LOG_LEVEL_INFO,
               "QUANX_REMOTE_RESOURCE_CREATED group_id=" +
                   std::to_string(remote.group_id) + " interval=" +
                   (remote.has_update_interval
                        ? std::to_string(remote.update_interval)
                        : std::string("client-default")) +
                   " source=" + summarizeUrlForLog(remote.url));
      ext.quanx_server_remotes.push_back(std::move(remote));
    }

    if (!node_urls.empty()) {
      for (const QuanXNodeLinkItem &item : node_urls) {
        string_array import_urls{item.url};
        if (importItems(import_urls, true, FetchContext::PublicRequest) != 0) {
          source_calls++;
          source_failures++;
          continue;
        }
        for (std::string &x : import_urls) {
          source_calls++;
          parse_settings item_parse_set = parse_set;
          item_parse_set.force_direct_link = item.force_direct_link;
          if (addNodes(x, nodes, item.group_id, item_parse_set) == -1) {
            source_failures++;
            writeLog(LOG_LEVEL_WARNING,
                     "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                         "，继续处理其他节点。");
          }
        }
      }
    }
    if (subscription_urls.empty()) {
      remote_mode = RemoteSubscriptionMode::ServerSideParse;
      remote_reason = "no-remote-subscription";
      explain.remote_subscription_backend =
          remoteSubscriptionModeName(remote_mode);
      explain.remote_subscription_reason = remote_reason;
    }
  } else if (stash_remote_eligible) {
    struct StashRemoteLinkItem {
      std::string url;
      std::string source_tag;
      std::string requested_name;
      int interval = 3600;
      int group_id = 0;
    };
    struct StashNodeLinkItem {
      std::string url;
      int group_id = 0;
      bool force_direct_link = false;
    };
    std::vector<StashRemoteLinkItem> subscription_urls;
    std::vector<StashNodeLinkItem> node_urls;

    for (size_t index = 0; index < urls.size(); ++index) {
      std::string &x = urls[index];
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }
      const std::string link = tagged.link.empty() ? x : tagged.link;
      const bool is_remote_subscription = isHttpSubscriptionLink(
          link, tagged.has_provider || tagged.has_interval);
      const int item_group_id = groupID++;

      if (is_remote_subscription) {
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        if (tagged.has_interval && tagged.interval <= 0) {
          *status_code = 400;
          return {true, surgePolicyPathIntervalError(index)};
        }
        if (hasUnsafeQuanXRemoteUrlChar(link)) {
          *status_code = 400;
          return {true, stashProxyProviderSourceError(index)};
        }
        writeLog(LOG_LEVEL_INFO,
                 "检测到 Stash proxy-provider 远程订阅：" +
                     summarizeUrlForLog(link) + "，将由客户端更新。");
        subscription_urls.push_back(
            {link, tagged.tag, tagged.provider,
             tagged.has_interval ? tagged.interval : 3600, item_group_id});
        explain.subscription_url_count++;
        continue;
      }

      if (tagged.has_interval) {
        *status_code = 400;
        return {true, providerIntervalScopeError(index)};
      }
      if (tagged.has_proxy_direct) {
        *status_code = 400;
        return {true, providerDirectScopeError(index)};
      }
      std::string node_link = link;
      if (tagged.has_tag)
        node_link = "tag:" + tagged.tag + "," + link;
      node_urls.push_back(
          {std::move(node_link), item_group_id, isLegacyHttpProxyUri(link)});
      explain.node_link_count++;
    }

    std::unordered_set<std::string> provider_names;

    size_t generated_index = 0;
    for (const StashRemoteLinkItem &item : subscription_urls) {
      std::string requested = sanitizeRemoteResourceName(item.requested_name);
      if (requested.empty())
        requested =
            "SubConverter_Provider_" + std::to_string(++generated_index);

      StashProxyProvider provider;
      provider.name = reserveStashProviderName(requested, provider_names);
      provider.requested_name = item.requested_name;
      provider.selection_name = provider.name;
      provider.source_tag = item.source_tag;
      provider.url = item.url;
      provider.path = "./providers/" + provider.name + ".yaml";
      provider.interval = item.interval;
      provider.group_id = item.group_id;
      provider.headers = provider_headers;
      writeLog(LOG_LEVEL_INFO,
               "STASH_PROXY_PROVIDER_CREATED group_id=" +
                   std::to_string(provider.group_id) + " interval=" +
                   std::to_string(provider.interval) + " source=" +
                   summarizeUrlForLog(provider.url));
      SubExplainProvider explain_provider;
      explain_provider.backend = "stash-client";
      explain_provider.name = provider.name;
      explain_provider.tag = provider.source_tag;
      explain_provider.source_summary = summarizeUrlForLog(provider.url);
      explain_provider.path = provider.path;
      explain_provider.name_generated = item.requested_name.empty();
      explain_provider.group_id = provider.group_id;
      explain_provider.interval = provider.interval;
      explain_provider.proxy_direct = false;
      explain.providers.push_back(std::move(explain_provider));
      ext.stash_proxy_providers.push_back(std::move(provider));
    }

    for (const StashNodeLinkItem &item : node_urls) {
      string_array import_urls{item.url};
      if (importItems(import_urls, true, FetchContext::PublicRequest) != 0) {
        source_calls++;
        source_failures++;
        continue;
      }
      for (std::string &x : import_urls) {
        source_calls++;
        parse_settings item_parse_set = parse_set;
        item_parse_set.force_direct_link = item.force_direct_link;
        if (addNodes(x, nodes, item.group_id, item_parse_set) == -1) {
          source_failures++;
          writeLog(LOG_LEVEL_WARNING,
                   "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                       "，继续处理其他节点。");
        }
      }
    }
  } else if (loon_remote_eligible) {
    struct LoonRemoteLinkItem {
      std::string url;
      std::string source_tag;
      std::string requested_name;
      int group_id = 0;
    };
    struct LoonNodeLinkItem {
      std::string url;
      int group_id = 0;
      bool force_direct_link = false;
    };
    std::vector<LoonRemoteLinkItem> subscription_urls;
    std::vector<LoonNodeLinkItem> node_urls;

    for (size_t index = 0; index < urls.size(); ++index) {
      std::string &x = urls[index];
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }
      std::string link = tagged.link.empty() ? x : tagged.link;
      const bool is_remote_subscription =
          isHttpSubscriptionLink(link, tagged.has_provider);
      const int item_group_id = groupID++;

      if (is_remote_subscription) {
        if (tagged.has_interval) {
          *status_code = 400;
          return {true, providerIntervalScopeError(index)};
        }
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        if (hasUnsafeQuanXRemoteUrlChar(link)) {
          *status_code = 400;
          return {true, loonRemoteProxySourceError(index)};
        }
        writeLog(LOG_LEVEL_INFO,
                 "检测到 Loon Remote Proxy 远程订阅：" +
                     summarizeUrlForLog(link) + "，将由客户端更新。");
        subscription_urls.push_back(
            {link, tagged.tag, tagged.provider, item_group_id});
        explain.subscription_url_count++;
        continue;
      }

      if (tagged.has_interval) {
        *status_code = 400;
        return {true, providerIntervalScopeError(index)};
      }
      if (tagged.has_proxy_direct) {
        *status_code = 400;
        return {true, providerDirectScopeError(index)};
      }
      std::string node_link = link;
      if (tagged.has_tag)
        node_link = "tag:" + tagged.tag + "," + link;
      node_urls.push_back(
          {std::move(node_link), item_group_id, isLegacyHttpProxyUri(link)});
      explain.node_link_count++;
    }

    std::unordered_set<std::string> resource_names;
    auto reserve_resource_name = [&](const std::string &base) {
      std::string base_name = clampProviderNameLength(base, 64);
      if (base_name.empty())
        base_name = "SubConverter_Remote";
      if (resource_names.insert(base_name).second)
        return base_name;
      int suffix_index = 1;
      while (true) {
        const std::string suffix = "_" + std::to_string(suffix_index++);
        const size_t max_base = 64 > suffix.size() ? 64 - suffix.size() : 0;
        const std::string candidate =
            clampProviderNameLength(base_name, max_base) + suffix;
        if (resource_names.insert(candidate).second)
          return candidate;
      }
    };

    size_t generated_index = 0;
    for (const LoonRemoteLinkItem &item : subscription_urls) {
      std::string requested = sanitizeRemoteResourceName(item.requested_name);
      if (requested.empty())
        requested =
            "SubConverter_Remote_" + std::to_string(++generated_index);

      LoonRemoteProxyResource remote;
      remote.resource_name = reserve_resource_name(requested);
      remote.requested_name = item.requested_name;
      remote.selection_name = remote.resource_name;
      remote.source_tag = item.source_tag;
      remote.url = item.url;
      remote.group_id = item.group_id;
      writeLog(LOG_LEVEL_INFO,
               "LOON_REMOTE_PROXY_CREATED group_id=" +
                   std::to_string(remote.group_id) + " source=" +
                   summarizeUrlForLog(remote.url));
      ext.loon_remote_proxies.push_back(std::move(remote));
    }

    for (const LoonNodeLinkItem &item : node_urls) {
      string_array import_urls{item.url};
      if (importItems(import_urls, true, FetchContext::PublicRequest) != 0) {
        source_calls++;
        source_failures++;
        continue;
      }
      for (std::string &x : import_urls) {
        source_calls++;
        parse_settings item_parse_set = parse_set;
        item_parse_set.force_direct_link = item.force_direct_link;
        if (addNodes(x, nodes, item.group_id, item_parse_set) == -1) {
          source_failures++;
          writeLog(LOG_LEVEL_WARNING,
                   "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                       "，继续处理其他节点。");
        }
      }
    }
  } else if (surge_remote_eligible || surfboard_remote_eligible) {
    struct PolicyPathRemoteLinkItem {
      std::string url;
      std::string source_tag;
      std::string requested_name;
      int interval = 0;
      bool has_interval = false;
      int group_id = 0;
    };
    struct PolicyPathNodeLinkItem {
      std::string url;
      int group_id = 0;
      bool force_direct_link = false;
    };
    std::vector<PolicyPathRemoteLinkItem> subscription_urls;
    std::vector<PolicyPathNodeLinkItem> node_urls;

    for (size_t index = 0; index < urls.size(); ++index) {
      std::string &x = urls[index];
      x = regTrim(x);
      TaggedLink tagged = parseTaggedLink(x);
      if (tagged.error != TaggedLink::Error::None) {
        *status_code = 400;
        return {true, providerLinkPrefixError(index, tagged.error)};
      }

      std::string link = tagged.link.empty() ? x : tagged.link;
      const bool is_remote_subscription = isHttpSubscriptionLink(
          link, tagged.has_provider ||
                    (surge_remote_eligible && tagged.has_interval));
      const int item_group_id = groupID++;
      if (is_remote_subscription) {
        if (tagged.has_proxy_direct) {
          *status_code = 400;
          return {true, providerDirectScopeError(index)};
        }
        if (surfboard_remote_eligible && tagged.has_interval) {
          *status_code = 400;
          return {true, providerIntervalScopeError(index)};
        }
        if (surge_remote_eligible && tagged.has_interval &&
            tagged.interval <= 0) {
          *status_code = 400;
          return {true, surgePolicyPathIntervalError(index)};
        }
        if (hasUnsafeQuanXRemoteUrlChar(link)) {
          *status_code = 400;
          return {true, surge_remote_eligible
                            ? surgePolicyPathSourceError(index)
                            : surfboardPolicyPathSourceError(index)};
        }
        writeLog(LOG_LEVEL_INFO,
                 std::string("检测到 ") +
                     (surge_remote_eligible ? "Surge" : "Surfboard") +
                     " policy-path 远程订阅：" +
                     summarizeUrlForLog(link) + "，将由客户端更新。");
        subscription_urls.push_back({link, tagged.tag, tagged.provider,
                                     tagged.interval, tagged.has_interval,
                                     item_group_id});
        explain.subscription_url_count++;
        continue;
      }

      if (tagged.has_interval) {
        *status_code = 400;
        return {true, providerIntervalScopeError(index)};
      }
      if (tagged.has_proxy_direct) {
        *status_code = 400;
        return {true, providerDirectScopeError(index)};
      }
      std::string node_link = link;
      if (tagged.has_tag)
        node_link = "tag:" + tagged.tag + "," + link;
      node_urls.push_back(
          {std::move(node_link), item_group_id, isLegacyHttpProxyUri(link)});
      explain.node_link_count++;
    }

    for (const PolicyPathRemoteLinkItem &item : subscription_urls) {
      if (surge_remote_eligible) {
        SurgePolicyPathResource resource;
        resource.url = item.url;
        resource.source_tag = item.source_tag;
        resource.requested_name = item.requested_name;
        resource.update_interval = item.interval;
        resource.has_update_interval = item.has_interval;
        resource.group_id = item.group_id;
        writeLog(LOG_LEVEL_INFO,
                 "SURGE_POLICY_PATH_CREATED group_id=" +
                     std::to_string(resource.group_id) + " interval=" +
                     (resource.has_update_interval
                          ? std::to_string(resource.update_interval)
                          : std::string("client-default")) +
                     " source=" + summarizeUrlForLog(resource.url));
        ext.surge_policy_paths.push_back(std::move(resource));
      } else {
        SurfboardPolicyPathResource resource;
        resource.url = item.url;
        resource.source_tag = item.source_tag;
        resource.requested_name = item.requested_name;
        resource.group_id = item.group_id;
        writeLog(LOG_LEVEL_INFO,
                 "SURFBOARD_POLICY_PATH_CREATED group_id=" +
                     std::to_string(resource.group_id) +
                     " interval=client-default source=" +
                     summarizeUrlForLog(resource.url));
        ext.surfboard_policy_paths.push_back(std::move(resource));
      }
    }

    for (const PolicyPathNodeLinkItem &item : node_urls) {
      string_array import_urls{item.url};
      if (importItems(import_urls, true, FetchContext::PublicRequest) != 0) {
        source_calls++;
        source_failures++;
        continue;
      }
      for (std::string &x : import_urls) {
        source_calls++;
        parse_settings item_parse_set = parse_set;
        item_parse_set.force_direct_link = item.force_direct_link;
        if (addNodes(x, nodes, item.group_id, item_parse_set) == -1) {
          source_failures++;
          writeLog(LOG_LEVEL_WARNING,
                   "已跳过无效节点链接：" + summarizeUrlForLog(x) +
                       "，继续处理其他节点。");
        }
      }
    }
  } else {
    importItems(urls, true, FetchContext::PublicRequest);
    for (std::string &x : urls) {
      x = regTrim(x);
      // std::cerr<<"Fetching node data from url '"<<x<<"'."<<std::endl;
      writeLog(0, "正在从 URL 获取节点数据：'" + x + "'。", LOG_LEVEL_INFO);
      if (addNodes(x, nodes, groupID, parse_set) == -1) {
        // 跳过无法解析的节点链接，记录警告后继续处理其他节点
        writeLog(0,
                 "已跳过无效节点链接：'" + x + "'，继续处理其他节点。",
                 LOG_LEVEL_WARNING);
      }
      groupID++;
    }
  }
  // exit if found nothing
  // 对于 proxy-provider 模式，允许 nodes 为空（节点从 provider 获取）
  explain.provider_count = ext.providers.size();
  explain.proxy_provider_mode = ext.use_proxy_provider && !ext.providers.empty();
  explain.insert_node_count = insert_nodes.size();
  explain.direct_node_count = nodes.size();
  if (!argProviderHeaders.empty() && !ext.nodelist && ext.providers.empty()) {
    *status_code = 400;
    return "Invalid request: provider_headers was selected, but no "
           "proxy-provider was generated.\n"
           "无效请求：已选择 provider_headers，但没有生成 proxy-provider。";
  }
  if (nodes.empty() && insert_nodes.empty() && ext.providers.empty()) {
    *status_code = 400;
    return {true,
            "Invalid request: provider_headers was selected, but no "
            "proxy-provider was generated.\n"
            "无效请求：已选择 provider_headers，但没有生成 proxy-provider。"};
  }
  if (nodes.empty() && insert_nodes.empty() && ext.providers.empty() &&
      ext.quanx_server_remotes.empty() && ext.surge_policy_paths.empty() &&
      ext.surfboard_policy_paths.empty() && ext.loon_remote_proxies.empty() &&
      ext.stash_proxy_providers.empty()) {
    *status_code = 400;
    return {true,
            "Invalid request: no valid proxy nodes or remote resources were "
            "found.\n"
            "无效请求：未找到有效的代理节点或远程资源。\n"
            "Please check whether the subscription URL or node URI format is "
            "supported, and whether filters excluded all nodes.\n"
            "请检查订阅链接或节点 URI 格式是否受支持，以及过滤规则是否排除了所有节点。"};
  }
  if (!subInfo.empty() && argAppendUserinfo.get(settings.appendUserinfo))
    response.headers.emplace("Subscription-UserInfo", subInfo);

  if (request.method == "HEAD")
    return {true, ""};

  if (argUpload && !isPublicUploadAllowed()) {
    *status_code = 403;
    return {true,
            "Upload is disabled for the current security profile.\n"
            "当前安全档位已禁用公开请求上传。\n"
            "Use security.profile=lan for private deployments, or explicitly "
            "enable security.allow_public_upload in public profile.\n"
            "内网私有部署请使用 security.profile=lan；公网档位如确需上传，"
            "请显式开启 security.allow_public_upload。"};
  }

  argPrependInsert.define(settings.prependInsert);
  if (argPrependInsert) {
    std::move(nodes.begin(), nodes.end(), std::back_inserter(insert_nodes));
    nodes.swap(insert_nodes);
  } else {
    std::move(insert_nodes.begin(), insert_nodes.end(),
              std::back_inserter(nodes));
  }

  std::string filterScript = settings.filterScript;
  if (!filterScript.empty()) {
    if (startsWith(filterScript, "path:"))
      filterScript = fileGet(filterScript.substr(5), false);
    /*
    duk_context *ctx = duktape_init();
    if(ctx)
    {
        defer(duk_destroy_heap(ctx);)
        if(duktape_peval(ctx, filterScript) == 0)
        {
            auto filter = [&](const Proxy &x)
            {
                duk_get_global_string(ctx, "filter");
                duktape_push_Proxy(ctx, x);
                duk_pcall(ctx, 1);
                return !duktape_get_res_bool(ctx);
            };
            nodes.erase(std::remove_if(nodes.begin(), nodes.end(), filter),
    nodes.end());
        }
        else
        {
            writeLog(0, "解析脚本时发生错误：\n" +
    duktape_get_err_stack(ctx), LOG_LEVEL_ERROR); duk_pop(ctx); /// pop err
        }
    }
    */
    script_safe_runner(
        ext.js_runtime, ext.js_context,
        [&](qjs::Context &ctx) {
          try {
            ctx.eval(filterScript);
            auto filter =
                (std::function<bool(const Proxy &)>)ctx.eval("filter");
            nodes.erase(std::remove_if(nodes.begin(), nodes.end(), filter),
                        nodes.end());
          } catch (qjs::exception) {
            script_print_stack(ctx);
          }
        },
        settings.scriptCleanContext);
  }

  if (!argGroupName.empty())
    for (Proxy &node : nodes)
      node.Group = argGroupName;

  preprocessNodes(nodes, ext);
  explain.total_node_count = nodes.size();

struct TargetGenerationState {
  std::string output;
  std::string managed_url;
  bool managed_url_from_profile_data = false;
  bool managed_url_used = false;
};

static uint64_t forceMaxGenerationWorkingEstimate(
    const std::vector<Proxy> &nodes,
    const ProxyGroupConfigs &groups,
    const std::vector<RulesetContent> &rulesets,
    const std::string *base_content, bool nodelist) noexcept {
  uint64_t total = UINT64_C(64) * 1024;
  auto add = [&](uint64_t value) {
    if (value > UINT64_MAX - total) {
      total = UINT64_MAX;
      return false;
    }
    total += value;
    return true;
  };
  auto scaled = [&](uint64_t value, uint64_t factor) {
    if (value != 0 && factor > UINT64_MAX / value)
      return UINT64_MAX;
    return value * factor;
  };
  auto string_bytes = [](const std::string &value) {
    return static_cast<uint64_t>(value.capacity());
  };
  auto add_to = [](uint64_t &target, uint64_t value) {
    if (value > UINT64_MAX - target) {
      target = UINT64_MAX;
      return false;
    }
    target += value;
    return true;
  };
  auto add_string_array = [&](uint64_t &bytes,
                              const std::vector<std::string> &values) {
    const uint64_t storage = scaled(values.capacity(),
                                    sizeof(std::string));
    if (storage == UINT64_MAX || bytes > UINT64_MAX - storage) {
      bytes = UINT64_MAX;
      return;
    }
    bytes += storage;
    for (const std::string &value : values) {
      const uint64_t retained = string_bytes(value);
      if (bytes > UINT64_MAX - retained) {
        bytes = UINT64_MAX;
        return;
      }
      bytes += retained;
    }
  };

  uint64_t maximum_remark = 0;
  for (const Proxy &proxy : nodes) {
    uint64_t bytes = sizeof(Proxy);
    const std::string *fields[] = {
        &proxy.Group, &proxy.Remark, &proxy.Hostname,
        &proxy.CongestionControl, &proxy.Username, &proxy.Password,
        &proxy.EncryptMethod, &proxy.Plugin, &proxy.PluginOption,
        &proxy.Protocol, &proxy.ProtocolParam, &proxy.OBFS,
        &proxy.OBFSParam, &proxy.UserId, &proxy.TransferProtocol,
        &proxy.FakeType, &proxy.AuthStr, &proxy.TLSStr, &proxy.Host,
        &proxy.Path, &proxy.Edge, &proxy.QUICSecure, &proxy.QUICSecret,
        &proxy.SnellUserKey, &proxy.SnellNetwork, &proxy.SnellMode,
        &proxy.ShadowTLSPassword, &proxy.ShadowTLSSNI,
        &proxy.ServerName, &proxy.SelfIP, &proxy.SelfIPv6,
        &proxy.PublicKey, &proxy.PrivateKey, &proxy.PreSharedKey,
        &proxy.AllowedIPs, &proxy.TestUrl, &proxy.ClientId,
        &proxy.WireGuardInterfaceName, &proxy.Ports, &proxy.Auth,
        &proxy.Alpn, &proxy.UpMbps, &proxy.DownMbps,
        &proxy.HysteriaHopInterval, &proxy.Insecure, &proxy.Fingerprint,
        &proxy.OBFSPassword, &proxy.Hysteria2RealmUrl,
        &proxy.Hysteria2GeckoMinPacketSize,
        &proxy.Hysteria2GeckoMaxPacketSize, &proxy.Hysteria2ECH,
        &proxy.GRPCServiceName, &proxy.GRPCMode, &proxy.ShortId,
        &proxy.Flow, &proxy.Encryption, &proxy.SNI, &proxy.UdpRelayMode,
        &proxy.token, &proxy.UnderlyingProxy, &proxy.PacketEncoding,
        &proxy.Multiplexing, &proxy.MieruProfile, &proxy.MieruSourceId,
        &proxy.MieruSourceRemark, &proxy.MieruHandshakeMode,
        &proxy.MieruTrafficPattern, &proxy.CanonicalProxyJson};
    for (const std::string *field : fields) {
      const uint64_t retained = string_bytes(*field);
      if (bytes > UINT64_MAX - retained) {
        bytes = UINT64_MAX;
        break;
      }
      bytes += retained;
    }
    add_string_array(bytes, proxy.DnsServers);
    add_string_array(bytes, proxy.WireGuardLocalAddresses);
    add_string_array(bytes, proxy.AlpnList);
    const uint64_t peer_storage = scaled(proxy.WireGuardPeers.capacity(),
                                         sizeof(WireGuardPeer));
    if (peer_storage == UINT64_MAX || bytes > UINT64_MAX - peer_storage)
      bytes = UINT64_MAX;
    else
      bytes += peer_storage;
    for (const WireGuardPeer &peer : proxy.WireGuardPeers) {
      const std::string *peer_fields[] = {
          &peer.Hostname, &peer.PublicKey, &peer.PreSharedKey,
          &peer.AllowedIPs, &peer.Reserved};
      for (const std::string *field : peer_fields) {
        const uint64_t retained = string_bytes(*field);
        if (bytes > UINT64_MAX - retained) {
          bytes = UINT64_MAX;
          break;
        }
        bytes += retained;
      }
    }
    const uint64_t option_storage = scaled(
        proxy.XrayLinkOptions.capacity(),
        sizeof(std::pair<std::string, std::string>));
    if (option_storage == UINT64_MAX || bytes > UINT64_MAX - option_storage)
      bytes = UINT64_MAX;
    else
      bytes += option_storage;
    for (const auto &[name, value] : proxy.XrayLinkOptions) {
      if (!add_to(bytes, string_bytes(name)) ||
          !add_to(bytes, string_bytes(value)))
        break;
    }
    maximum_remark = std::max(maximum_remark,
                              string_bytes(proxy.Remark));
    if (!add(scaled(bytes, 8)) || !add(4096))
      return UINT64_MAX;
  }

  for (const ProxyGroupConfig &group : groups) {
    uint64_t bytes = sizeof(ProxyGroupConfig);
    (void)add_to(bytes, string_bytes(group.Name));
    (void)add_to(bytes, string_bytes(group.Url));
    add_string_array(bytes, group.Proxies);
    add_string_array(bytes, group.UsingProvider);
    if (!add(scaled(bytes, 8)) || !add(2048))
      return UINT64_MAX;
  }

  if (!nodelist && !nodes.empty() && !groups.empty()) {
    uint64_t references = scaled(nodes.size(), groups.size());
    const uint64_t per_reference =
        maximum_remark > (UINT64_MAX - 512) / 4
            ? UINT64_MAX
            : maximum_remark * 4 + 512;
    references = scaled(references, per_reference);
    if (!add(references))
      return UINT64_MAX;
  }

  for (const RulesetContent &ruleset : rulesets) {
    uint64_t bytes = sizeof(RulesetContent);
    (void)add_to(bytes, string_bytes(ruleset.rule_group));
    (void)add_to(bytes, string_bytes(ruleset.rule_path));
    (void)add_to(bytes, string_bytes(ruleset.rule_path_typed));
    if (ruleset.resolved_content) {
      const uint64_t retained = ruleset.resolved_content->capacity();
      if (bytes > UINT64_MAX - retained)
        bytes = UINT64_MAX;
      else
        bytes += retained;
    }
    if (!add(scaled(bytes, 4)) || !add(2048))
      return UINT64_MAX;
  }
  if (base_content && !add(scaled(base_content->capacity(), 4)))
    return UINT64_MAX;
  return total;
}

struct PendingUpload {
  std::string name;
  std::string path;
  bool write_manage_url = false;
};

static SubStageResponse dispatchTargetGenerator(
    Request &request, Response &response, const Settings &settings,
    ParsedSubRequest &parsed, EffectiveSubPolicy &policy,
    ExternalConfigFetchPlan &fetch_plan,
    SubscriptionNodeState &subscription, TargetGenerationState &generation,
    const std::string *resolved_base_content = nullptr,
    std::vector<PendingUpload> *deferred_uploads = nullptr,
    size_t max_output_bytes = std::numeric_limits<size_t>::max()) {
  auto &argument = request.argument;
  int *status_code = &response.status_code;
  auto &target = parsed.target;
  auto &surge_version_text = parsed.surge_version_text;
  auto &group_name = parsed.group_name;
  auto &upload_path = parsed.upload_path;
  auto &upload = parsed.upload;
  auto &ext = policy.generator;
  auto &template_arguments = policy.template_arguments;
  auto &proxy = policy.subscription_proxy;
  auto &nodes = subscription.nodes;
  auto &subscription_info = subscription.subscription_info;
  auto &ruleset_content = fetch_plan.ruleset_content;
  const FetchContext base_context = fetch_plan.base_fetch_context;
  std::string base_content;
  std::string &output = generation.output;
  ProxyGroupConfigs dummy_group;
  std::vector<RulesetContent> dummy_ruleset;
  auto renderBase = [&](const std::string &path) {
    if (resolved_base_content) {
      base_content = *resolved_base_content;
      return 0;
    }
    return render_template(
        fetchFile(path, proxy, settings.cacheConfig, true, base_context),
        template_arguments, base_content, settings.templatePath,
        base_context);
  };

  std::string &managed_url = generation.managed_url;
  managed_url = base64Decode(getUrlArg(argument, "profile_data"));
  generation.managed_url_from_profile_data = !managed_url.empty();
  if (managed_url.empty())
    managed_url =
        settings.managedConfigPrefix + "/sub?" + joinArguments(argument);

  std::vector<PendingUpload> pending_uploads;
  bool upload_failed = false;
  auto recordUpload = [&](const std::string &name, const std::string &path,
                          const std::string &content, bool write_manage_url) {
    (void)content;
    pending_uploads.push_back({name, path, write_manage_url});
  };

  proxy = parseProxy(settings.proxyConfig, settings.proxyBypass);
  prepareTargetTemplateArguments(parsed, policy);
  switch (hash_(target)) {
  case "clash"_hash:
  case "clashr"_hash:
    writeLog(0,
             argTarget == "clashr" ? "生成目标：ClashR" : "生成目标：Clash",
             LOG_LEVEL_INFO);
    tpl_args.local_vars["clash.new_field_name"] =
        ext.clash_new_field_name ? "true" : "false";
    response.headers["profile-update-interval"] =
        std::to_string(policy.update_interval / 3600);
    if (ext.nodelist) {
      YAML::Node yamlnode;
      proxyToClash(nodes, yamlnode, dummy_group, target == "clashr", ext);
      output = dumpCanonicalClashYaml(yamlnode, max_output_bytes);
    } else {
      if (renderBase(policy.clash_base) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
      output = proxyToClash(nodes, base_content, ruleset_content,
                            policy.custom_proxy_groups, target == "clashr",
                            ext, max_output_bytes);
      if (!ext.external_rule_error.empty()) {
        *status_code = 400;
        return {true, ext.external_rule_error};
      }
    }
    if (upload)
      recordUpload(target, upload_path, output, false);
    break;

  case "surge"_hash:

    writeLog(0, "生成目标：Surge " + std::to_string(intSurgeVer),
             LOG_LEVEL_INFO);

    if (ext.nodelist) {
      output = proxyToSurge(nodes, base_content, dummy_ruleset, dummy_group,
                            parsed.surge_version, ext, max_output_bytes);
    } else {
      if (renderBase(policy.surge_base) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
      output = proxyToSurge(nodes, base_content, ruleset_content,
                            policy.custom_proxy_groups, parsed.surge_version,
                            ext, max_output_bytes);
    }

    {
      const TargetGenerationStats &stats = ext.surge_generation_stats;
      string_array unsupported_protocols;
      unsupported_protocols.reserve(stats.unsupported_by_type.size());
      for (const auto &[type, count] : stats.unsupported_by_type) {
        unsupported_protocols.emplace_back(toLower(getProxyTypeName(type)) +
                                           ":" + std::to_string(count));
      }
      const size_t unsupported_count = stats.unsupported_nodes();
      writeLog(unsupported_count ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO,
               "SURGE_NODE_GENERATION input=" +
                   std::to_string(stats.input_nodes) + " emitted=" +
                   std::to_string(stats.emitted_nodes) + " unsupported=" +
                   std::to_string(unsupported_count) + " protocols=" +
                   (unsupported_protocols.empty()
                        ? std::string("none")
                        : join(unsupported_protocols, ";")) +
                   " remote_references=" +
                   std::to_string(stats.remote_references_emitted));
      parsed.explain.generated_node_count = stats.emitted_nodes;
      parsed.explain.unsupported_node_count = unsupported_count;
      parsed.explain.unsupported_protocols = unsupported_protocols;

      if (!ext.surge_policy_paths.empty() &&
          stats.remote_references_emitted == 0) {
        *status_code = 400;
        return {true,
                "Invalid request: the Surge policy-path subscription was not "
                "selected by any compatible proxy group.\n"
                "无效请求：没有兼容的策略组选择该 Surge policy-path 订阅。"};
      }
    }

    if (upload)
      recordUpload(ext.nodelist ? "surge" + surge_version_text + "list"
                                : "surge" + surge_version_text,
                   upload_path, output, true);
    if (!ext.nodelist) {
      if (settings.writeManagedConfig && !settings.managedConfigPrefix.empty())
        generation.managed_url_used = true;
      if (generation.managed_url_used)
        {
          if (output.capacity() > max_output_bytes)
            throw BoundedOutputExceeded();
          BoundedOutputSink prefix(
              (max_output_bytes - output.capacity()) / 2);
          prefix.append("#!MANAGED-CONFIG ");
          prefix.append(managed_url);
          if (policy.update_interval) {
            prefix.append(" interval=");
            prefix.append(std::to_string(policy.update_interval));
          }
          prefix.append(" strict=");
          prefix.append(policy.update_strict ? "true" : "false");
          prefix.append("\n\n");
          output = boundedConcatWithRetained(prefix.release(), output,
                                             max_output_bytes);
        }
    }
    break;

  case "surfboard"_hash:
    writeLog(0, "生成目标：Surfboard", LOG_LEVEL_INFO);

    if (render_template(fetchFile(lSurfboardBase, proxy, global.cacheConfig,
                                  true, baseFetchContext),
                        tpl_args, base_content, global.templatePath,
                        baseFetchContext) != 0) {
      *status_code = 400;
      return {true, base_content};
    }
    output = proxyToSurge(nodes, base_content, ruleset_content,
                          policy.custom_proxy_groups, -3, ext,
                          max_output_bytes);
    {
      const TargetGenerationStats &stats = ext.surfboard_generation_stats;
      string_array unsupported_protocols;
      unsupported_protocols.reserve(stats.unsupported_by_type.size());
      for (const auto &[type, count] : stats.unsupported_by_type) {
        unsupported_protocols.emplace_back(toLower(getProxyTypeName(type)) +
                                           ":" + std::to_string(count));
      }
      const size_t unsupported_count = stats.unsupported_nodes();
      writeLog(unsupported_count ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO,
               "SURFBOARD_NODE_GENERATION input=" +
                   std::to_string(stats.input_nodes) + " emitted=" +
                   std::to_string(stats.emitted_nodes) + " unsupported=" +
                   std::to_string(unsupported_count) + " protocols=" +
                   (unsupported_protocols.empty()
                        ? std::string("none")
                        : join(unsupported_protocols, ";")) +
                   " remote_references=" +
                   std::to_string(stats.remote_references_emitted));
      parsed.explain.generated_node_count = stats.emitted_nodes;
      parsed.explain.unsupported_node_count = unsupported_count;
      parsed.explain.unsupported_protocols = unsupported_protocols;

      if (!ext.surfboard_policy_paths.empty() &&
          stats.remote_references_emitted == 0) {
        *status_code = 400;
        return {true,
                "Invalid request: the Surfboard policy-path subscription was "
                "not selected by any compatible proxy group.\n"
                "无效请求：没有兼容的策略组选择该 Surfboard policy-path "
                "订阅。"};
      }
    }
    if (upload)
      recordUpload("surfboard", upload_path, output, true);
    if (!ext.nodelist) {
      if (settings.writeManagedConfig && !settings.managedConfigPrefix.empty())
        generation.managed_url_used = true;
      if (generation.managed_url_used)
        {
          if (output.capacity() > max_output_bytes)
            throw BoundedOutputExceeded();
          BoundedOutputSink prefix(
              (max_output_bytes - output.capacity()) / 2);
          prefix.append("#!MANAGED-CONFIG ");
          prefix.append(managed_url);
          if (policy.update_interval > 0) {
            prefix.append(" interval=");
            prefix.append(std::to_string(policy.update_interval));
          }
          prefix.append(" strict=");
          prefix.append(policy.update_strict ? "true" : "false");
          prefix.append("\n\n");
          output = boundedConcatWithRetained(prefix.release(), output,
                                             max_output_bytes);
        }
    }
    break;

  case "stash"_hash:
    writeLog(LOG_LEVEL_INFO, "生成目标：Stash");
    if (renderBase(policy.stash_base) != 0) {
      *status_code = 400;
      return {true, base_content};
    }
    output = proxyToStash(nodes, base_content, ruleset_content,
                          policy.custom_proxy_groups, ext, max_output_bytes);
    parsed.explain.rule_provider_count =
        ext.stash_rule_stats.final_provider_count;
    parsed.explain.inline_rule_source_count =
        ext.stash_rule_stats.inline_sources;
    parsed.explain.expanded_rule_source_count =
        ext.stash_rule_stats.expanded_sources;
    parsed.explain.unsupported_ruleset_count =
        ext.stash_rule_stats.unsupported_sources;
    if (!ext.external_rule_error.empty()) {
      *status_code = 400;
      return {true, ext.external_rule_error};
    }
    if (ext.stash_proxy_providers.size() !=
        ext.target_generation_stats.remote_references_emitted) {
      *status_code = 400;
      return {true,
              "Invalid request: every Stash proxy-provider must be selected "
              "by a compatible proxy group.\n"
              "无效请求：每个 Stash proxy-provider 都必须被兼容的策略组"
              "选中。"};
    }
    if (upload)
      recordUpload("stash", upload_path, output, false);
    break;

  case "mellow"_hash:
    writeLog(0, "生成目标：Mellow", LOG_LEVEL_INFO);

    if (render_template(fetchFile(lMellowBase, proxy, global.cacheConfig, true,
                                  baseFetchContext),
                        tpl_args, base_content, global.templatePath,
                        baseFetchContext) != 0) {
      *status_code = 400;
      return {true, base_content};
    }
    output = proxyToMellow(nodes, base_content, ruleset_content,
                           policy.custom_proxy_groups, ext, max_output_bytes);
    if (upload)
      recordUpload("mellow", upload_path, output, true);
    break;

  case "sssub"_hash:
    writeLog(0, "生成目标：SS Subscription", LOG_LEVEL_INFO);

    if (render_template(fetchFile(lSSSubBase, proxy, global.cacheConfig, true,
                                  baseFetchContext),
                        tpl_args, base_content, global.templatePath,
                        baseFetchContext) != 0) {
      *status_code = 400;
      return {true, base_content};
    }
    output = proxyToSSSub(base_content, nodes, ext, max_output_bytes);
    if (upload)
      recordUpload("sssub", upload_path, output, false);
    break;

  case "ss"_hash:
    writeLog(0, "生成目标：SS", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 1, ext);
    if (argUpload)
      uploadGist("ss", argUploadPath, output_content, false);
    break;
  case "ssr"_hash:
    writeLog(0, "生成目标：SSR", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 2, ext);
    if (argUpload)
      uploadGist("ssr", argUploadPath, output_content, false);
    break;
  case "v2ray"_hash:
    writeLog(0, "生成目标：v2rayN", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 4, ext);
    if (argUpload)
      uploadGist("v2ray", argUploadPath, output_content, false);
    break;
  case "trojan"_hash:
    writeLog(0, "生成目标：Trojan", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 8, ext);
    if (argUpload)
      uploadGist("trojan", argUploadPath, output_content, false);
    break;
  case "vless"_hash:
    writeLog(0, "生成目标：vless", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 16, ext);
    if (argUpload)
      uploadGist("vless", argUploadPath, output_content, false);
    break;
  case "hysteria2"_hash:
    writeLog(0, "生成目标：hysteria2", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 32, ext);
    if (argUpload)
      uploadGist("hysteria2", argUploadPath, output_content, false);
    break;
  case "mixed"_hash:
    writeLog(0, "生成目标：Standard Subscription", LOG_LEVEL_INFO);
    output_content = proxyToSingle(nodes, 63, ext);
    if (argUpload)
      uploadGist("sub", argUploadPath, output_content, false);
    break;

  case "quan"_hash:
    writeLog(0, "生成目标：Quantumult", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (renderBase(policy.quan_base) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
    }
    output = proxyToQuan(nodes, base_content, ruleset_content,
                         policy.custom_proxy_groups, ext, max_output_bytes);
    if (upload)
      recordUpload("quan", upload_path, output, false);
    break;

  case "quanx"_hash:
    writeLog(0, "生成目标：Quantumult X", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (renderBase(policy.quanx_base) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
    }
    output = proxyToQuanX(nodes, base_content, ruleset_content,
                          policy.custom_proxy_groups, ext, max_output_bytes);
    if (upload)
      recordUpload("quanx", upload_path, output, false);
    break;

  case "loon"_hash:
    writeLog(0, "生成目标：Loon", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (renderBase(policy.loon_base) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
    }
    output = proxyToLoon(nodes, base_content, ruleset_content,
                         policy.custom_proxy_groups, ext, max_output_bytes);
    {
      const TargetGenerationStats &stats = ext.loon_generation_stats;
      string_array unsupported_protocols;
      unsupported_protocols.reserve(stats.unsupported_by_type.size());
      for (const auto &[type, count] : stats.unsupported_by_type) {
        unsupported_protocols.emplace_back(toLower(getProxyTypeName(type)) +
                                           ":" + std::to_string(count));
      }
      const size_t unsupported_count = stats.unsupported_nodes();
      writeLog(unsupported_count ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO,
               "LOON_NODE_GENERATION input=" +
                   std::to_string(stats.input_nodes) + " emitted=" +
                   std::to_string(stats.emitted_nodes) + " unsupported=" +
                   std::to_string(unsupported_count) + " protocols=" +
                   (unsupported_protocols.empty()
                        ? std::string("none")
                        : join(unsupported_protocols, ";")) +
                   " remote_references=" +
                   std::to_string(stats.remote_references_emitted));
      parsed.explain.generated_node_count = stats.emitted_nodes;
      parsed.explain.unsupported_node_count = unsupported_count;
      parsed.explain.unsupported_protocols = unsupported_protocols;

      if (!ext.loon_remote_proxies.empty() &&
          stats.remote_references_emitted == 0) {
        *status_code = 400;
        return {true,
                "Invalid request: no compatible Loon proxy group selected "
                "the Remote Proxy subscription.\n"
                "无效请求：没有兼容的 Loon 策略组选择 Remote Proxy 订阅。"};
      }
    }
    if (upload)
      recordUpload("loon", upload_path, output, false);
    break;

  case "ssd"_hash:
    writeLog(0, "生成目标：SSD", LOG_LEVEL_INFO);
    output_content = proxyToSSD(nodes, argGroupName, subInfo, ext);
    if (argUpload)
      uploadGist("ssd", argUploadPath, output_content, false);
    break;

  case "singbox"_hash:
    writeLog(0, "生成目标：sing-box", LOG_LEVEL_INFO);
    if (!ext.nodelist) {
      if (renderBase(policy.singbox_base) != 0) {
        *status_code = 400;
        return {true, base_content};
      }
    }
    output = proxyToSingBox(nodes, base_content, ruleset_content,
                            policy.custom_proxy_groups, ext,
                            max_output_bytes);
    if (upload)
      recordUpload("singbox", upload_path, output, false);
    break;

  default:
    writeLog(0, "生成目标：未指定", LOG_LEVEL_INFO);
    *status_code = 500;
    return {true,
            "Internal error: target passed validation but no generator handled "
            "it.\n"
            "内部错误：target 已通过校验，但没有对应的生成器处理它。\n"
            "Please report this request to the service maintainer.\n"
            "请将该请求反馈给服务维护者。"};
  }

  if (parsed.target_descriptor->parser_mode == NodeParserMode::LegacyOnly) {
    const TargetGenerationStats &stats = ext.target_generation_stats;
    string_array unsupported_protocols;
    unsupported_protocols.reserve(stats.unsupported_by_type.size());
    for (const auto &[type, count] : stats.unsupported_by_type) {
      unsupported_protocols.emplace_back(toLower(getProxyTypeName(type)) +
                                         ":" + std::to_string(count));
    }
    const size_t unsupported_count = stats.unsupported_nodes();
    writeLog(unsupported_count ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO,
             "TARGET_NODE_GENERATION target=" + target + " input=" +
                 std::to_string(stats.input_nodes) + " emitted=" +
                 std::to_string(stats.emitted_nodes) + " unsupported=" +
                 std::to_string(unsupported_count) + " protocols=" +
                 (unsupported_protocols.empty()
                      ? std::string("none")
                      : join(unsupported_protocols, ";")) +
                 " remote_references=" +
                 std::to_string(stats.remote_references_emitted));
    parsed.explain.generated_node_count = stats.emitted_nodes;
    parsed.explain.unsupported_node_count = unsupported_count;
    parsed.explain.unsupported_protocols = unsupported_protocols;

    if (stats.input_nodes > 0 && stats.emitted_nodes == 0 &&
        stats.remote_references_emitted == 0) {
      *status_code = 400;
      return {true,
              "Invalid request: none of the parsed proxy nodes can be "
              "represented by the selected output target.\n"
              "无效请求：解析到的代理节点均无法由所选输出目标表示。"};
    }
  }

  if (deferred_uploads) {
    *deferred_uploads = std::move(pending_uploads);
  } else {
    for (const PendingUpload &pending : pending_uploads) {
      if (uploadGist(pending.name, pending.path, output,
                     pending.write_manage_url) != 0)
        upload_failed = true;
    }
  }

  if (upload_failed)
    writeLog(LOG_LEVEL_WARNING,
             "GIST_OPTIONAL_UPLOAD_FAILED action=return-conversion-result");
  writeLog(LOG_LEVEL_INFO, "生成完成。");
  return {};
}

static std::string assembleSubResponse(
    Request &request, Response &response, const Settings &settings,
    ParsedSubRequest &parsed, EffectiveSubPolicy &policy,
    ExternalConfigFetchPlan &fetch_plan, TargetGenerationState &generation,
    size_t max_output_bytes = std::numeric_limits<size_t>::max()) {
  auto &argument = request.argument;
  std::string &argTarget = parsed.target;
  bool explainMode = parsed.explain_mode;
  SubExplainReport &explain = parsed.explain;
  tribool &argClashNewField = parsed.clash_new_field;
  int intSurgeVer = parsed.surge_version;
  std::string &argGroupName = parsed.group_name;
  std::string &argUploadPath = parsed.upload_path;
  std::string &argIncludeRemark = parsed.include_remark;
  std::string &argExcludeRemark = parsed.exclude_remark;
  std::string &argFilename = parsed.filename;
  std::string &argRenames = parsed.renames;
  tribool &argUpload = parsed.upload;
  tribool &argAddEmoji = parsed.add_emoji;
  tribool &argRemoveEmoji = parsed.remove_emoji;
  tribool &argAppendType = parsed.append_type;
  tribool &argSort = parsed.sort;
  tribool &argUseSortScript = parsed.use_sort_script;
  tribool &argGenClashScript = parsed.generate_clash_script;
  tribool &argEnableInsert = parsed.enable_insert;
  tribool &argFilterDeprecated = parsed.filter_deprecated;
  tribool &argExpandRulesets = parsed.expand_rulesets;
  tribool &argAppendUserinfo = parsed.append_userinfo;
  tribool &argPrependInsert = parsed.prepend_insert;
  tribool &argGenClassicalRuleProvider =
      parsed.generate_classical_rule_provider;
  tribool &argProviderProxyDirect = parsed.provider_proxy_direct;
  string_array &lIncludeRemarks = policy.include_remarks;
  string_array &lExcludeRemarks = policy.exclude_remarks;
  extra_settings &ext = policy.generator;
  int interval = policy.update_interval;
  bool strict = policy.update_strict;
  std::map<std::string, std::string> &provider_headers =
      policy.provider_headers;
  bool userProvidedExternalConfig =
      fetch_plan.user_provided_external_config;
  std::string &output_content = generation.output;
  std::string &managed_url = generation.managed_url;

  for (const auto &[name, value] : provider_headers) {
    (void)value;
    appendVaryHeader(response, name);
  }

  if (explainMode) {
    auto hasArg = [&](const std::string &name) {
      return argument.find(name) != argument.end();
    };
    auto rawArg = [&](const std::string &name) {
      return getUrlArg(argument, name);
    };
    auto addParameter = [&](const std::string &name,
                            const std::string &effective_value,
                            const std::string &status,
                            const std::string &note,
                            bool sensitive = false,
                            const std::string &source = "request") {
      if (!hasArg(name))
        return;
      std::string raw_value = rawArg(name);
      SubExplainParameter parameter;
      parameter.name = name;
      parameter.present = true;
      parameter.source = source;
      parameter.status = status;
      parameter.value_preview = previewExplainValue(raw_value, sensitive);
      parameter.value_hash.clear();
      parameter.raw_length = raw_value.size();
      parameter.value_length = raw_value.size();
      parameter.effective_value = previewExplainValue(effective_value, false);
      parameter.note = note;
      parameter.sensitive = sensitive;
      explain.recognized_parameters.push_back(std::move(parameter));
    };
    auto addSwitchParameter = [&](const std::string &name, bool effective_value,
                                  const tribool &arg_value,
                                  const std::string &note = "") {
      addParameter(name, boolString(effective_value),
                   arg_value.is_undef() ? "defaulted" : "applied", note);
    };
    auto addConfigSection = [&](const std::string &name,
                                const std::string &source,
                                const std::string &status,
                                const std::string &detail) {
      SubExplainConfigSection section;
      section.name = name;
      section.source = source;
      section.status = status;
      section.detail = detail;
      explain.effective_config_sections.push_back(std::move(section));
    };

    addParameter("target", argTarget,
                 explain.requested_target != argTarget ? "resolved" : "applied",
                 explain.requested_target != argTarget
                     ? "target=auto was resolved from the User-Agent"
                     : "");
    addParameter("url",
                 std::to_string(explain.raw_url_count) +
                     " source item(s), " +
                     std::to_string(explain.subscription_url_count) +
                     " subscription(s), " +
                     std::to_string(explain.node_link_count) +
                     " node link(s); sources: " +
                     summarizeExplainSourceList(rawArg("url")),
                 "applied",
                 "Sensitive values are redacted; use lengths and structural "
                 "summaries to compare inputs.",
                 true);
    addParameter("explain", "true", "applied",
                 "The request returned a JSON diagnostic report.");
    addParameter("ver", std::to_string(intSurgeVer), "applied",
                 "Surge-compatible target version.");
    addParameter("new_name", boolString(ext.clash_new_field_name),
                 argClashNewField.is_undef() ||
                         argClashNewField.get(false) == ext.clash_new_field_name
                     ? "applied"
                     : "overridden",
                 "Mihomo-compatible field names are forced for Clash output.");
    addParameter("group", argGroupName,
                 argGroupName.empty() ? "ignored" : "applied",
                 "Overrides the group name on direct nodes.");
    addParameter("upload_path",
                 argUploadPath.empty() ? "not provided" : "provided",
                  argUpload ? "applied" : "ignored",
                  "Only used when upload is effective.", true);
    addParameter("include", argIncludeRemark,
                 !argIncludeRemark.empty() && regValid(argIncludeRemark)
                     ? "applied"
                     : "ignored",
                 "Used as node/provider include filter when valid.");
    addParameter("exclude", argExcludeRemark,
                 !argExcludeRemark.empty() && regValid(argExcludeRemark)
                     ? "applied"
                     : "ignored",
                 "Used as node/provider exclude filter when valid.");
    addParameter("groups", "not consumed", "ignored",
                 "This compatibility parameter is not consumed by /sub.",
                 true);
    addParameter("ruleset", "not consumed", "ignored",
                 "This compatibility parameter is not consumed by /sub.",
                 true);
    const bool request_config_provided = !parsed.external_config.empty();
    std::string config_effective = explain.external_config_loaded
                                       ? "loaded"
                                       : "not loaded";
    if (explain.fallback_config_used)
      config_effective = "fallback loaded";
    if (!rawArg("config").empty())
      config_effective +=
          "; requested source: " + summarizeUrlForLog(rawArg("config"));
    const std::string config_status =
        explain.fallback_config_used
            ? "overridden"
            : (request_config_provided
                   ? (explain.external_config_loaded ? "applied" : "ignored")
                   : (explain.external_config_loaded ? "defaulted"
                                                     : "ignored"));
    const std::string config_source =
        explain.fallback_config_used
            ? "fallback"
            : (request_config_provided
                   ? "request"
                   : (explain.external_config_loaded ? "default" : "request"));
    addParameter("config", config_effective, config_status,
                 explain.fallback_config_used
                     ? "User config failed and a fallback config was loaded."
                     : "External config URL or data source.",
                 true, config_source);
    const bool request_device_id_applied = !parsed.device_id.empty();
    const bool effective_device_id_configured = !ext.quanx_dev_id.empty();
    addParameter(
        "dev_id",
        effective_device_id_configured ? "configured" : "not configured",
        request_device_id_applied
            ? "applied"
            : (effective_device_id_configured ? "defaulted" : "ignored"),
        request_device_id_applied
            ? "Quantumult X device ID."
            : (effective_device_id_configured
                   ? "Empty request value; the configured device ID remained "
                     "effective."
                   : "No effective Quantumult X device ID is configured."),
        true, request_device_id_applied
                  ? "request"
                  : (effective_device_id_configured ? "default" : "request"));
    addParameter("filename", argFilename, "ignored",
                 "Content-Disposition is not emitted for explain JSON.");
    addParameter("interval", std::to_string(interval), "applied",
                 "Effective update interval in seconds.");
    addParameter("strict", boolString(strict), "applied",
                 "Managed config strict flag.");
    addParameter("rename", std::to_string(ext.rename_array.size()) +
                               " rename rule(s)",
                  argRenames.empty() ? "ignored" : "applied",
                  "Request rename rules override configured rename rules.",
                  true);
    addParameter("filter_script", "not used", "ignored",
                 "Public requests cannot provide executable filter scripts.",
                 true);
    addParameter("provider_headers",
                 std::to_string(provider_headers.size()) +
                     " explicitly selected header(s)",
                 provider_headers.empty() ? "ignored" : "applied",
                 "Only named, present, non-reserved request headers are "
                 "copied into generated Clash or Stash proxy-providers.");
    addParameter("upload", boolString(argUpload), explain.upload_suppressed
                                                    ? "suppressed"
                                                    : "applied",
                 explain.upload_suppressed
                     ? "Uploads are disabled in explain mode."
                     : "");
    addParameter("emoji", boolString(ext.add_emoji), "applied",
                 "Sets add_emoji and remove_emoji together.");
    addSwitchParameter("add_emoji", ext.add_emoji, argAddEmoji);
    addSwitchParameter("remove_emoji", ext.remove_emoji, argRemoveEmoji);
    addSwitchParameter("append_type", ext.append_proxy_type, argAppendType);
    addSwitchParameter("tfo", ext.tfo.get(false), ext.tfo);
    addSwitchParameter("udp", ext.udp.get(false), ext.udp);
    addParameter("list", boolString(ext.nodelist), "applied",
                  ext.nodelist
                      ? "Explicit node-list mode expands subscription sources."
                      : (argTarget == "quanx"
                             ? "Quantumult X full-config output uses client-managed "
                               "server_remote resources when the request can be "
                               "represented without losing advanced semantics."
                             : (argTarget == "stash"
                                    ? "Stash full-config output uses named client-managed "
                                      "proxy-providers when the request can be represented "
                                      "without losing advanced semantics."
                                    : "Clash-compatible output defaults to provider mode.")));
    addSwitchParameter("sort", ext.sort_flag, argSort);
    addParameter("sort_script",
                 argUseSortScript ? "enabled" : "disabled",
                 argUseSortScript ? "applied" : "ignored",
                 "Uses configured sort script when sorting is enabled.");
    addSwitchParameter("script", ext.clash_script, argGenClashScript);
    addSwitchParameter("insert", argEnableInsert.get(settings.enableInsert),
                       argEnableInsert);
    addSwitchParameter("scv", ext.skip_cert_verify.get(false),
                       ext.skip_cert_verify);
    addSwitchParameter("fdn", ext.filter_deprecated, argFilterDeprecated);
    addSwitchParameter("expand", explain.expand_rulesets, argExpandRulesets);
    addSwitchParameter("append_info",
                       argAppendUserinfo.get(settings.appendUserinfo),
                       argAppendUserinfo);
    addSwitchParameter("prepend", argPrependInsert.get(settings.prependInsert),
                       argPrependInsert);
    addSwitchParameter("classic", ext.clash_classical_ruleset,
                       argGenClassicalRuleProvider);
    addSwitchParameter("tls13", ext.tls13.get(false), ext.tls13);
    addSwitchParameter("provider_proxy_direct", ext.provider_proxy_direct,
                       argProviderProxyDirect);
    std::string profile_effective = "not used";
    std::string profile_status = "ignored";
    std::string profile_source = "request";
    std::string profile_note =
        "This target did not emit a managed configuration URL.";
    if (generation.managed_url_used) {
      profile_effective = generation.managed_url_from_profile_data
                              ? "provided"
                              : "generated";
      profile_effective += "; source: " + summarizeUrlForLog(managed_url);
      profile_status = generation.managed_url_from_profile_data
                           ? "applied"
                           : "defaulted";
      profile_source = generation.managed_url_from_profile_data ? "request"
                                                                 : "global";
      profile_note = generation.managed_url_from_profile_data
                         ? "Managed configuration URL override."
                         : "A managed configuration URL was generated.";
    }
    addParameter("profile_data", profile_effective, profile_status,
                 profile_note, true, profile_source);
    addParameter("token", "not used", "ignored",
                 "Token authentication is disabled.", true);

    const std::unordered_set<std::string> known_parameters = {
        "target", "url", "ver", "new_name", "group", "upload_path",
        "include", "exclude", "groups", "ruleset", "config", "dev_id",
        "filename", "interval", "strict", "rename", "filter_script",
        "upload", "emoji", "add_emoji", "remove_emoji", "append_type",
        "tfo", "udp", "list", "sort", "sort_script", "script", "insert",
        "scv", "fdn", "expand", "append_info", "prepend", "classic",
        "tls13", "provider_proxy_direct", "provider_headers", "explain",
        "profile_data", "token"};
    for (const auto &arg : argument) {
      if (known_parameters.find(arg.first) != known_parameters.end())
        continue;
      SubExplainParameter parameter;
      parameter.name = explainParameterName(arg.first);
      parameter.present = true;
      parameter.source = "request";
      parameter.status = "ignored";
      parameter.value_preview = previewExplainValue(arg.second, true);
      parameter.value_hash.clear();
      parameter.raw_length = arg.second.size();
      parameter.value_length = arg.second.size();
      parameter.effective_value = "";
      parameter.note = parameter.name == "[redacted-name]"
                           ? "The parameter name and value were redacted."
                           : "This parameter is not recognized by /sub; its "
                             "value was redacted.";
      parameter.sensitive = true;
      explain.unrecognized_parameters.push_back(std::move(parameter));
    }

    if (explain.fallback_config_used)
      explain.effective_config_source = "fallback";
    else if (explain.external_config_loaded && userProvidedExternalConfig)
      explain.effective_config_source = "request";
    else if (explain.external_config_loaded && !settings.defaultExtConfig.empty())
      explain.effective_config_source = "default";
    else if (userProvidedExternalConfig)
      explain.effective_config_source = "request_failed";
    else
      explain.effective_config_source = "none";

    if (explain.external_config_provided || explain.external_config_loaded) {
      addConfigSection("external_config", explain.effective_config_source,
                       explain.external_config_loaded ? "loaded" : "not_loaded",
                       explain.fallback_config_used
                           ? "Fallback config was used."
                           : (userProvidedExternalConfig
                                  ? "User-provided config was evaluated."
                                  : "Default external config was evaluated."));
    }
    addConfigSection("base_template", explain.base_fetch_context, "selected",
                     "Base template fetch context for target " + argTarget +
                         ".");
    if (explain.rule_generator_enabled)
      addConfigSection("rulesets", explain.ruleset_fetch_context, "loaded",
                       std::to_string(explain.ruleset_count) +
                           " ruleset(s).");
    if (explain.custom_group_count)
      addConfigSection("custom_groups", "effective", "loaded",
                       std::to_string(explain.custom_group_count) +
                           " custom group(s).");
    if (!ext.rename_array.empty())
      addConfigSection("rename", argRenames.empty() ? "configured" : "request",
                       "loaded",
                       std::to_string(ext.rename_array.size()) +
                           " rename rule(s).");
    if (!ext.emoji_array.empty())
      addConfigSection("emoji", "configured", "loaded",
                       std::to_string(ext.emoji_array.size()) +
                           " emoji rule(s).");
    if (!lIncludeRemarks.empty() || !lExcludeRemarks.empty())
      addConfigSection("filters", "effective", "loaded",
                       std::to_string(lIncludeRemarks.size()) +
                           " include filter(s), " +
                           std::to_string(lExcludeRemarks.size()) +
                           " exclude filter(s).");
    if (explain.provider_count)
      addConfigSection("proxy_providers", "request", "generated",
                       std::to_string(explain.provider_count) +
                           " provider(s).");
    if (explain.remote_subscription_count) {
      std::string remote_section = "quanx_server_remote";
      if (explain.remote_subscription_backend == "surge-policy-path")
        remote_section = "surge_policy_path";
      else if (explain.remote_subscription_backend ==
               "surfboard-policy-path")
        remote_section = "surfboard_policy_path";
      else if (explain.remote_subscription_backend == "loon-remote-proxy")
        remote_section = "loon_remote_proxy";
      else if (explain.remote_subscription_backend ==
               "stash-proxy-provider")
        remote_section = "stash_proxy_provider";
      addConfigSection(remote_section, "request", "generated",
                       std::to_string(explain.remote_subscription_count) +
                           " remote resource(s); node-name transformations run "
                           "only in the client or its configured resource parser.");
    }
    if (explain.managed_config)
      addConfigSection("managed_config", "global", "enabled",
                       "Managed config prefix is available.");

    explain.output_bytes = output_content.size();
    writeLog(LOG_LEVEL_INFO,
             "已生成 /sub explain JSON 诊断结果：target=" + argTarget +
                 ", status=" + std::to_string(response.status_code) +
                 ", providers=" + std::to_string(explain.provider_count) +
                 ", remote_resources=" +
                 std::to_string(explain.remote_subscription_count) +
                 ", nodes=" + std::to_string(explain.total_node_count) +
                 ", recognized_params=" +
                 std::to_string(explain.recognized_parameters.size()) +
                 ", unrecognized_params=" +
                 std::to_string(explain.unrecognized_parameters.size()) + "。");
    // Explain returns a diagnostic document, not the generated target body.
    // Release that potentially large body before allocating the bounded JSON
    // staging/result pair so the force_max owner envelope is not triple-held.
    std::string().swap(output_content);
    response.content_type = "application/json; charset=utf-8";
    return serializeSubExplainReport(explain, response, max_output_bytes);
  }
  writeLog(0, "生成完成。", LOG_LEVEL_INFO);
  if (argTarget == "clash" && explain.proxy_provider_mode)
    appendVaryHeader(response, "User-Agent");
  for (const auto &[name, value] : provider_headers) {
    (void)value;
    appendVaryHeader(response, name);
  }

  if (explainMode) {
    auto hasArg = [&](const std::string &name) {
      return argument.find(name) != argument.end();
    };
    auto rawArg = [&](const std::string &name) {
      return getUrlArg(argument, name);
    };
    auto addParameter = [&](const std::string &name,
                            const std::string &effective_value,
                            const std::string &status,
                            const std::string &note,
                            bool sensitive = false,
                            const std::string &source = "request") {
      if (!hasArg(name))
        return;
      std::string raw_value = rawArg(name);
      std::string decoded_value = urlDecode(raw_value);
      SubExplainParameter parameter;
      parameter.name = name;
      parameter.present = true;
      parameter.source = source;
      parameter.status = status;
      parameter.value_preview = previewExplainValue(raw_value, sensitive);
      parameter.value_hash = shortHash(decoded_value);
      parameter.raw_length = raw_value.size();
      parameter.value_length = decoded_value.size();
      parameter.effective_value = effective_value;
      parameter.note = note;
      parameter.sensitive = sensitive;
      explain.recognized_parameters.push_back(std::move(parameter));
    };
    auto addSwitchParameter = [&](const std::string &name, bool effective_value,
                                  const tribool &arg_value,
                                  const std::string &note = "") {
      addParameter(name, boolString(effective_value),
                   arg_value.is_undef() ? "defaulted" : "applied", note);
    };
    auto addConfigSection = [&](const std::string &name,
                                const std::string &source,
                                const std::string &status,
                                const std::string &detail) {
      SubExplainConfigSection section;
      section.name = name;
      section.source = source;
      section.status = status;
      section.detail = detail;
      explain.effective_config_sections.push_back(std::move(section));
    };

    addParameter("target", argTarget,
                 explain.requested_target != argTarget ? "resolved" : "applied",
                 explain.requested_target != argTarget
                     ? "target=auto was resolved from the User-Agent"
                     : "");
    addParameter("url",
                 std::to_string(explain.raw_url_count) +
                     " source item(s), " +
                     std::to_string(explain.subscription_url_count) +
                     " subscription(s), " +
                     std::to_string(explain.node_link_count) + " node link(s)",
                 "applied",
                 "Sensitive values are redacted; use hash and length to "
                 "compare inputs.",
                 true);
    addParameter("explain", "true", "applied",
                 "The request returned a JSON diagnostic report.");
    addParameter("ver", std::to_string(intSurgeVer), "applied",
                 "Surge-compatible target version.");
    addParameter("new_name", boolString(ext.clash_new_field_name),
                 argClashNewField.is_undef() ||
                         argClashNewField.get(false) == ext.clash_new_field_name
                     ? "applied"
                     : "overridden",
                 "Mihomo-compatible field names are forced for Clash output.");
    addParameter("group", argGroupName,
                 argGroupName.empty() ? "ignored" : "applied",
                 "Overrides the group name on direct nodes.");
    addParameter("upload_path", argUploadPath,
                 argUpload ? "applied" : "ignored",
                 "Only used when upload is effective.", true);
    addParameter("include", argIncludeRemark,
                 !argIncludeRemark.empty() && regValid(argIncludeRemark)
                     ? "applied"
                     : "ignored",
                 "Used as node/provider include filter when valid.");
    addParameter("exclude", argExcludeRemark,
                 !argExcludeRemark.empty() && regValid(argExcludeRemark)
                     ? "applied"
                     : "ignored",
                 "Used as node/provider exclude filter when valid.");
    addParameter("groups", std::to_string(lCustomProxyGroups.size()) +
                              " custom group(s)",
                 configLoadSuccess ? "ignored" : "applied",
                 configLoadSuccess
                     ? "External config loaded; request groups were not used."
                     : "Decoded from URL-safe base64.");
    addParameter("ruleset", std::to_string(lRulesetContent.size()) +
                                " loaded ruleset(s)",
                 configLoadSuccess ? "ignored" : "applied",
                 configLoadSuccess
                     ? "External config loaded; request rulesets were not used."
                     : "Decoded from URL-safe base64.");
    std::string config_effective = explain.external_config_loaded
                                       ? "loaded"
                                       : "not loaded";
    if (explain.fallback_config_used)
      config_effective = "fallback loaded";
    addParameter("config", config_effective,
                 explain.external_config_loaded ? "applied" : "ignored",
                 explain.fallback_config_used
                     ? "User config failed and a fallback config was loaded."
                     : "External config URL or data source.",
                 true);
    addParameter("dev_id", ext.quanx_dev_id,
                 ext.quanx_dev_id.empty() ? "ignored" : "applied",
                 "Quantumult X device id.");
    addParameter("filename", argFilename, "ignored",
                 "Content-Disposition is not emitted for explain JSON.");
    addParameter("interval", std::to_string(interval), "applied",
                 "Effective update interval in seconds.");
    addParameter("strict", boolString(strict), "applied",
                 "Managed config strict flag.");
    addParameter("rename", std::to_string(ext.rename_array.size()) +
                               " rename rule(s)",
                 argRenames.empty() ? "ignored" : "applied",
                 "Request rename rules override configured rename rules.");
    addParameter("filter_script",
                 authorized && !argFilterScript.empty() ? "script accepted"
                                                        : "not used",
                 authorized ? "applied" : "ignored",
                  "Public requests cannot provide executable filter scripts.",
                  true);
    addParameter("provider_headers",
                 std::to_string(provider_headers.size()) +
                     " explicitly selected header(s)",
                 provider_headers.empty() ? "ignored" : "applied",
                 "Only named, present, non-reserved request headers are "
                 "copied into generated proxy-providers.");
    addParameter("upload", boolString(argUpload), explain.upload_suppressed
                                                    ? "suppressed"
                                                    : "applied",
                 explain.upload_suppressed
                     ? "Uploads are disabled in explain mode."
                     : "");
    addParameter("emoji", boolString(ext.add_emoji), "applied",
                 "Sets add_emoji and remove_emoji together.");
    addSwitchParameter("add_emoji", ext.add_emoji, argAddEmoji);
    addSwitchParameter("remove_emoji", ext.remove_emoji, argRemoveEmoji);
    addSwitchParameter("append_type", ext.append_proxy_type, argAppendType);
    addSwitchParameter("tfo", ext.tfo.get(false), ext.tfo);
    addSwitchParameter("udp", ext.udp.get(false), ext.udp);
    addParameter("list", boolString(ext.nodelist), "applied",
                 ext.nodelist
                     ? "Explicit node-list mode expands subscription sources."
                     : "Clash-compatible output defaults to provider mode.");
    addSwitchParameter("sort", ext.sort_flag, argSort);
    addParameter("sort_script",
                 argUseSortScript ? "enabled" : "disabled",
                 argUseSortScript ? "applied" : "ignored",
                 "Uses configured sort script when sorting is enabled.");
    addSwitchParameter("script", ext.clash_script, argGenClashScript);
    addSwitchParameter("insert", argEnableInsert.get(global.enableInsert),
                       argEnableInsert);
    addSwitchParameter("scv", ext.skip_cert_verify.get(false),
                       ext.skip_cert_verify);
    addSwitchParameter("fdn", ext.filter_deprecated, argFilterDeprecated);
    addSwitchParameter("expand", explain.expand_rulesets, argExpandRulesets);
    addSwitchParameter("append_info",
                       argAppendUserinfo.get(global.appendUserinfo),
                       argAppendUserinfo);
    addSwitchParameter("prepend", argPrependInsert.get(global.prependInsert),
                       argPrependInsert);
    addSwitchParameter("classic", ext.clash_classical_ruleset,
                       argGenClassicalRuleProvider);
    addSwitchParameter("tls13", ext.tls13.get(false), ext.tls13);
    addSwitchParameter("provider_proxy_direct", ext.provider_proxy_direct,
                       argProviderProxyDirect);
    addParameter("profile_data", managed_url.empty() ? "not used" : "provided",
                 managed_url.empty() ? "ignored" : "applied",
                 "Managed config URL override.", true);

    const std::unordered_set<std::string> known_parameters = {
        "target", "url", "ver", "new_name", "group", "upload_path",
        "include", "exclude", "groups", "ruleset", "config", "dev_id",
        "filename", "interval", "strict", "rename", "filter_script",
        "upload", "emoji", "add_emoji", "remove_emoji", "append_type",
        "tfo", "udp", "list", "sort", "sort_script", "script", "insert",
        "scv", "fdn", "expand", "append_info", "prepend", "classic",
        "tls13", "provider_proxy_direct", "provider_headers", "explain",
        "profile_data", "token"};
    for (const auto &arg : argument) {
      if (known_parameters.find(arg.first) != known_parameters.end())
        continue;
      std::string decoded_value = urlDecode(arg.second);
      SubExplainParameter parameter;
      parameter.name = arg.first;
      parameter.present = true;
      parameter.source = "request";
      parameter.status = "ignored";
      parameter.value_preview = previewExplainValue(arg.second, false);
      parameter.value_hash = shortHash(decoded_value);
      parameter.raw_length = arg.second.size();
      parameter.value_length = decoded_value.size();
      parameter.effective_value = "";
      parameter.note = "This parameter is not recognized by /sub.";
      parameter.sensitive = false;
      explain.unrecognized_parameters.push_back(std::move(parameter));
    }

    if (explain.fallback_config_used)
      explain.effective_config_source = "fallback";
    else if (explain.external_config_loaded && userProvidedExternalConfig)
      explain.effective_config_source = "request";
    else if (explain.external_config_loaded && !global.defaultExtConfig.empty())
      explain.effective_config_source = "default";
    else if (userProvidedExternalConfig)
      explain.effective_config_source = "request_failed";
    else
      explain.effective_config_source = "none";

    if (explain.external_config_provided || explain.external_config_loaded) {
      addConfigSection("external_config", explain.effective_config_source,
                       explain.external_config_loaded ? "loaded" : "not_loaded",
                       explain.fallback_config_used
                           ? "Fallback config was used."
                           : (userProvidedExternalConfig
                                  ? "User-provided config was evaluated."
                                  : "Default external config was evaluated."));
    }
    addConfigSection("base_template", explain.base_fetch_context, "selected",
                     "Base template fetch context for target " + argTarget +
                         ".");
    if (explain.rule_generator_enabled)
      addConfigSection("rulesets", explain.ruleset_fetch_context, "loaded",
                       std::to_string(explain.ruleset_count) +
                           " ruleset(s).");
    if (explain.custom_group_count)
      addConfigSection("custom_groups", "effective", "loaded",
                       std::to_string(explain.custom_group_count) +
                           " custom group(s).");
    if (!ext.rename_array.empty())
      addConfigSection("rename", argRenames.empty() ? "configured" : "request",
                       "loaded",
                       std::to_string(ext.rename_array.size()) +
                           " rename rule(s).");
    if (!ext.emoji_array.empty())
      addConfigSection("emoji", "configured", "loaded",
                       std::to_string(ext.emoji_array.size()) +
                           " emoji rule(s).");
    if (!lIncludeRemarks.empty() || !lExcludeRemarks.empty())
      addConfigSection("filters", "effective", "loaded",
                       std::to_string(lIncludeRemarks.size()) +
                           " include filter(s), " +
                           std::to_string(lExcludeRemarks.size()) +
                           " exclude filter(s).");
    if (explain.provider_count)
      addConfigSection("proxy_providers", "request", "generated",
                       std::to_string(explain.provider_count) +
                           " provider(s).");
    if (explain.managed_config)
      addConfigSection("managed_config", "global", "enabled",
                       "Managed config prefix is available.");

    explain.output_bytes = output_content.size();
    writeLog(0,
             "已生成 /sub explain JSON 诊断结果：target=" + argTarget +
                 ", status=" + std::to_string(response.status_code) +
                 ", providers=" + std::to_string(explain.provider_count) +
                 ", nodes=" + std::to_string(explain.total_node_count) +
                 ", recognized_params=" +
                 std::to_string(explain.recognized_parameters.size()) +
                 ", unrecognized_params=" +
                 std::to_string(explain.unrecognized_parameters.size()) + "。",
             LOG_LEVEL_INFO);
    response.content_type = "application/json; charset=utf-8";
    return serializeSubExplainReport(explain, response);
  }
  if (!argFilename.empty())
    response.headers.emplace("Content-Disposition",
                             "attachment; filename=\"" + argFilename +
                                 "\"; filename*=utf-8''" +
                                 urlEncode(argFilename));
  return std::move(output_content);
}

} // namespace

static std::string subconverter_impl(Request &request, Response &response,
                                     const Settings &settings,
                                     RuleConversionStats *rule_stats) {
  auto cancelled = [&]() -> std::optional<std::string> {
    RequestCancellationResponse cancellation_response;
    if (!requestCancellationResponse(request.context,
                                     cancellation_response))
      return std::nullopt;
    response.status_code = cancellation_response.status_code;
    response.content_type = "text/plain; charset=utf-8";
    response.headers = std::move(cancellation_response.headers);
    return std::move(cancellation_response.body);
  };
  ParsedSubRequest parsed_request;
  EffectiveSubPolicy effective_policy;
  ExternalConfigFetchPlan fetch_plan;
  SubscriptionNodeState subscription_state;
  TargetGenerationState generation_state;
  std::optional<RequestStageTimer> serialize_timer;

  return runConversionPipeline({
      .cancellation = cancelled,
      .parse_and_policy = [&]() -> ConversionPipelineStepResult {
        RequestStageTimer parse_timer(request.context, RequestStage::Parse);
        std::string parse_error = parseSubRequestArguments(
            request, response, settings, parsed_request);
        if (!parse_error.empty())
          return {true, std::move(parse_error)};

        std::string policy_error = buildEffectiveSubPolicy(
            request, response, settings, rule_stats, parsed_request,
            effective_policy);
        if (!policy_error.empty())
          return {true, std::move(policy_error)};
        return {};
      },
      .dependency_plan = [&]() -> ConversionPipelineStepResult {
        RequestStageTimer rules_timer(request.context, RequestStage::Rules);
        std::string fetch_plan_error = buildExternalConfigFetchPlan(
            response, settings, parsed_request, effective_policy, fetch_plan);
        if (!fetch_plan_error.empty())
          return {true, std::move(fetch_plan_error)};
        return {};
      },
      .subscription = [&]() -> ConversionPipelineStepResult {
        RequestStageTimer parse_timer(request.context, RequestStage::Parse);
        SubStageResponse result = processSubscriptionNodes(
            request, response, settings, parsed_request, effective_policy,
            subscription_state);
        if (request.context) {
          const bool high_cost =
              parsed_request.explain.subscription_url_count > 1 ||
              effective_policy.custom_rulesets.size() > 1 ||
              parsed_request.generate_clash_script.get(false) ||
              !parsed_request.external_config.empty();
          request.context->setCostClass(
              parsed_request.explain.proxy_provider_mode
                  ? RequestCostClass::Low
                  : (high_cost ? RequestCostClass::High
                               : RequestCostClass::Medium));
        }
        return result;
      },
      .generation = [&]() -> ConversionPipelineStepResult {
        serialize_timer.emplace(request.context, RequestStage::Serialize);
        return dispatchTargetGenerator(
            request, response, settings, parsed_request, effective_policy,
            fetch_plan, subscription_state, generation_state);
      },
      .assembly = [&] {
        return assembleSubResponse(request, response, settings, parsed_request,
                                   effective_policy, fetch_plan,
                                   generation_state);
      },
  });
}

void configureResponseMicroCacheLimit(uint64_t max_bytes) noexcept {
  g_sub_response_cache_limit.store(std::max<uint64_t>(1, max_bytes),
                                   std::memory_order_release);
  std::lock_guard<std::mutex> lock(g_sub_response_cache_mutex);
  while (!g_sub_response_cache.empty() &&
         g_sub_response_cache_bytes > max_bytes) {
    auto oldest = std::min_element(
        g_sub_response_cache.begin(), g_sub_response_cache.end(),
        [](const auto &left, const auto &right) {
          return left.second.sequence < right.second.sequence;
        });
    if (oldest == g_sub_response_cache.end())
      break;
    eraseSubResponseCacheEntry(oldest);
  }
}

void setResponseMicroCacheGrowthFrozen(bool frozen) noexcept {
  g_sub_response_cache_growth_frozen.store(frozen,
                                           std::memory_order_release);
}

namespace {

static bool forceMaxFlowEligible(
    const Request &request, const PreparedSubRequest &prepared) {
  (void)request;
  if (!prepared.settings ||
      prepared.settings->resourceControlEffective != "force_max")
    return false;
  // force_max is a startup contract. A request is never silently redirected
  // to a shared legacy scheduler because of its target or feature mix; if the
  // committed runtime is unavailable, startForceMaxFlow fails closed.
  return true;
}

class ForceMaxFlowState
    : public std::enable_shared_from_this<ForceMaxFlowState> {
public:
  ForceMaxFlowState(
      Request request, std::shared_ptr<const PreparedSubRequest> prepared,
      bool track_statistics, bool record_direct_statistics,
      ForceMaxFlowCompletion completion)
      : request_(std::move(request)), prepared_(std::move(prepared)),
        settings_(prepared_->settings),
        track_statistics_(track_statistics),
        record_direct_statistics_(record_direct_statistics),
        completion_(std::move(completion)) {
    const ResourceControlSnapshot resources = resourceControlSnapshot();
    const uint64_t maximum_download =
        settings_ && settings_->maxAllowedDownloadSize > 0
            ? static_cast<uint64_t>(settings_->maxAllowedDownloadSize)
            : 0;
    working_reservation_bytes_ = forceMaxOwnerWorkingReservation(
        resources.calculated_force_max_budget,
        request_.context ? request_.context->estimatedBytes() : 0,
        maximum_download);
  }

  bool start() {
    return startAttempt();
  }

private:
  struct ConfigCandidate {
    std::string path;
    FetchContext context = FetchContext::TrustedConfig;
    bool fallback = false;
  };

  struct AttemptCandidate {
    Response response;
    std::string body;
    uint64_t rule_conversions = 0;
    std::vector<PendingUpload> uploads;
  };

  bool startAttempt() {
    const uint64_t terminal_before =
        terminal_deliveries_.load(std::memory_order_acquire);
    ComputeExecutor *executor = globalComputeExecutor();
    if (!executor || !settings_ || !request_.context)
      return false;
    const ResourceControlSnapshot resources = resourceControlSnapshot();
    const ForceMaxBudget &budget =
        resources.calculated_force_max_budget;
    const RuntimeCoordinatorSnapshot coordinator =
        runtimeCoordinatorSnapshot();
    if (resources.effective_mode != "force_max" || !budget.valid ||
        !coordinator.force_max || !coordinator.prepared ||
        !coordinator.ready || coordinator.stopping ||
        coordinator.generation == 0)
      return false;
    const uint64_t flows = std::max<uint64_t>(1, budget.active_flows);
    const ConversionFlowBudget flow_budget{
        std::max<uint64_t>(8, budget.flow_queue_entries / flows),
        std::max<uint64_t>(UINT64_C(64) * 1024,
                           budget.flow_queue_bytes / flows)};
    try {
      auto self = shared_from_this();
      flow_ = ConversionFlow::create(
          *executor, flow_budget, settings_, request_.context,
          [self](ConversionFlowTerminal terminal) mutable {
            self->terminal(std::move(terminal));
          });
      if (!flow_)
        return terminal_deliveries_.load(std::memory_order_acquire) !=
               terminal_before;
      // Once a flow exists it owns terminal delivery. start() may return false
      // after a synchronous scheduler rejection, but that rejection already
      // invokes terminal(); reporting false to the caller would publish a
      // second completion for the same request.
      (void)flow_->start(
          [self](ConversionFlow &flow) { self->parse(flow); });
      return true;
    } catch (...) {
      flow_.reset();
      return terminal_deliveries_.load(std::memory_order_acquire) !=
             terminal_before;
    }
  }

  void resetAttemptState() {
    parsed_.reset();
    policy_.reset();
    fetch_plan_.reset();
    subscription_.reset();
    generation_.reset();
    response_ = {};
    rule_stats_ = {};
    template_local_base_.clear();
    config_candidates_.clear();
    config_candidate_index_ = 0;
    selected_config_.reset();
    missing_subscriptions_.clear();
    resolved_keys_.clear();
    resolved_subscriptions_ = {};
    dependency_requests_.clear();
    resolved_dependencies_ = {};
    planned_imports_.clear();
    missing_imports_.clear();
    resolved_imports_.clear();
    import_resolution_rounds_ = 0;
    resolved_base_content_.clear();
    working_source_charge_bytes_ = first_failure_charge_bytes_;
    generation_structure_charge_bytes_ = 0;
    pending_uploads_.clear();
    upload_index_ = 0;
    upload_failed_ = false;
    selected_body_.clear();
    quickjs_stage_ = {};
    quickjs_body_.clear();
    quickjs_generated_ = false;
    working_capacity_exceeded_ = false;
    finalized_ = false;
  }

  void failOrCancel(ConversionFlow &flow,
                    std::exception_ptr error) noexcept {
    if (!error) {
      (void)flow.fail({});
      return;
    }
    try {
      std::rethrow_exception(error);
    } catch (const SchedulerSubmitError &submit_error) {
      if (submit_error.status() == SchedulerSubmitStatus::Deadline) {
        flow.requestCancellation(RequestCancellationReason::Deadline);
        return;
      }
      if (submit_error.status() == SchedulerSubmitStatus::Stopping) {
        flow.requestCancellation(RequestCancellationReason::Shutdown);
        return;
      }
      if (submit_error.status() == SchedulerSubmitStatus::Cancelled) {
        RequestCancellationReason reason =
            request_.context->cancellationToken().reason();
        if (reason == RequestCancellationReason::None)
          reason = RequestCancellationReason::ClientDisconnected;
        flow.requestCancellation(reason);
        return;
      }
    } catch (...) {
    }
    (void)flow.fail(std::move(error));
  }

  bool handleAsyncFetchTerminal(ConversionFlow &flow,
                                AsyncFetchFailure failure) {
    switch (failure) {
    case AsyncFetchFailure::Capacity:
      working_capacity_exceeded_ = true;
      finishWorkingCapacity(flow);
      return true;
    case AsyncFetchFailure::Deadline:
      flow.requestCancellation(RequestCancellationReason::Deadline);
      return true;
    case AsyncFetchFailure::Shutdown:
      flow.requestCancellation(RequestCancellationReason::Shutdown);
      return true;
    case AsyncFetchFailure::Cancelled: {
      RequestCancellationReason reason =
          request_.context->cancellationToken().reason();
      if (reason == RequestCancellationReason::None)
        reason = RequestCancellationReason::ClientDisconnected;
      flow.requestCancellation(reason);
      return true;
    }
    case AsyncFetchFailure::None:
    case AsyncFetchFailure::SizeLimit:
    case AsyncFetchFailure::Dns:
    case AsyncFetchFailure::Tls:
    case AsyncFetchFailure::Proxy:
    case AsyncFetchFailure::Transport:
      return false;
    }
    return false;
  }

  bool handleExternalConfigTerminal(ConversionFlow &flow,
                                    ExternalConfigLoadStatus status) {
    switch (status) {
    case ExternalConfigLoadStatus::ResourceLimitExceeded:
      working_capacity_exceeded_ = true;
      finishWorkingCapacity(flow);
      return true;
    case ExternalConfigLoadStatus::Deadline:
      flow.requestCancellation(RequestCancellationReason::Deadline);
      return true;
    case ExternalConfigLoadStatus::Shutdown:
      flow.requestCancellation(RequestCancellationReason::Shutdown);
      return true;
    case ExternalConfigLoadStatus::Cancelled: {
      RequestCancellationReason reason =
          request_.context->cancellationToken().reason();
      if (reason == RequestCancellationReason::None)
        reason = RequestCancellationReason::ClientDisconnected;
      flow.requestCancellation(reason);
      return true;
    }
    case ExternalConfigLoadStatus::Success:
    case ExternalConfigLoadStatus::FetchFailed:
    case ExternalConfigLoadStatus::RenderFailed:
    case ExternalConfigLoadStatus::ParseFailed:
    case ExternalConfigLoadStatus::ImportFailed:
      return false;
    }
    return false;
  }

  bool handleTemplateTerminal(ConversionFlow &flow,
                              AsyncTemplateStatus status) {
    switch (status) {
    case AsyncTemplateStatus::ResourceLimitExceeded:
      working_capacity_exceeded_ = true;
      finishWorkingCapacity(flow);
      return true;
    case AsyncTemplateStatus::Deadline:
      flow.requestCancellation(RequestCancellationReason::Deadline);
      return true;
    case AsyncTemplateStatus::Shutdown:
      flow.requestCancellation(RequestCancellationReason::Shutdown);
      return true;
    case AsyncTemplateStatus::Cancelled: {
      RequestCancellationReason reason =
          request_.context->cancellationToken().reason();
      if (reason == RequestCancellationReason::None)
        reason = RequestCancellationReason::ClientDisconnected;
      flow.requestCancellation(reason);
      return true;
    }
    case AsyncTemplateStatus::Success:
    case AsyncTemplateStatus::FetchFailed:
    case AsyncTemplateStatus::RenderFailed:
      return false;
    }
    return false;
  }

  void collectImportSources(const std::string &value,
                            FetchContext context) {
    for (const std::string &item : split(value, "|")) {
      const size_t marker = item.find("!!import:");
      if (marker == std::string::npos)
        continue;
      // Preserve importItems' historical path extraction (the text after the
      // first colon), including its treatment of tagged request entries.
      const size_t colon = item.find(':');
      if (colon == std::string::npos || colon + 1 >= item.size())
        continue;
      const std::string path = item.substr(colon + 1);
      if (std::find_if(planned_imports_.begin(), planned_imports_.end(),
                       [&](const UnresolvedImportSource &source) {
                         return source.path == path &&
                                source.context == context;
                       }) == planned_imports_.end())
        planned_imports_.push_back({path, context});
    }
  }

  void planRequestImports() {
    planned_imports_.clear();
    collectImportSources(parsed_->url, FetchContext::PublicRequest);
    if (parsed_->enable_insert.get(false))
      collectImportSources(settings_->insertUrls,
                           FetchContext::TrustedConfig);
    const ProxyPolicy proxy =
        parseProxy(settings_->proxyConfig, settings_->proxyBypass);
    for (size_t index = 0; index < planned_imports_.size(); ++index) {
      AsyncConversionResourceRequest request;
      request.kind = ConversionResourceKind::SubscriptionImport;
      request.source_index = index;
      request.url = planned_imports_[index].path;
      request.proxy = proxy;
      request.cache_ttl = static_cast<unsigned int>(
          std::max(0, settings_->cacheConfig));
      request.context = planned_imports_[index].context;
      dependency_requests_.emplace_back(std::move(request));
    }
  }

  bool collectResolvedImports(
      const AsyncConversionResourceBatchResult &result,
      const std::vector<UnresolvedImportSource> &sources,
      std::string &error) {
    for (const ResolvedConversionResource &resource : result.resources) {
      if (resource.kind != ConversionResourceKind::SubscriptionImport ||
          resource.source_index >= sources.size())
        continue;
      const UnresolvedImportSource &source =
          sources[resource.source_index];
      if (!resource.payload ||
          resource.failure != AsyncFetchFailure::None ||
          resource.payload->content.empty()) {
        error = "Invalid request: an imported subscription source could not "
                "be resolved.\n"
                "无效请求：无法解析导入的订阅来源。";
        return false;
      }
      resolved_imports_[resolvedImportKey(source.path, source.context)] =
          resource.payload->content;
    }
    for (const UnresolvedImportSource &source : sources) {
      if (resolved_imports_.find(
              resolvedImportKey(source.path, source.context)) ==
          resolved_imports_.end()) {
        error = "Invalid request: an imported subscription source was not "
                "returned by the bounded resolver.\n"
                "无效请求：有导入的订阅来源未由有界解析器返回。";
        return false;
      }
    }
    return true;
  }

  void resolveMissingImports(ConversionFlow &flow) {
    if (missing_imports_.empty())
      return;
    if (++import_resolution_rounds_ > 8) {
      response_.status_code = 400;
      finishRawBody(flow,
                    "Invalid request: nested subscription imports exceed "
                    "the supported resolution depth.\n"
                    "无效请求：订阅导入嵌套超过支持的解析深度。");
      return;
    }
    std::vector<UnresolvedImportSource> sources;
    sources.swap(missing_imports_);
    const ProxyPolicy proxy =
        parseProxy(settings_->proxyConfig, settings_->proxyBypass);
    std::vector<AsyncConversionResourceRequest> requests;
    requests.reserve(sources.size());
    for (size_t index = 0; index < sources.size(); ++index) {
      AsyncConversionResourceRequest request;
      request.kind = ConversionResourceKind::SubscriptionImport;
      request.source_index = index;
      request.url = sources[index].path;
      request.proxy = proxy;
      request.cache_ttl = static_cast<unsigned int>(
          std::max(0, settings_->cacheConfig));
      request.context = sources[index].context;
      requests.emplace_back(std::move(request));
    }
    auto self = shared_from_this();
    if (!resolveConversionResourcesOnFlow(
            flow, std::move(requests), settings_, request_.context,
            [self, sources = std::move(sources)](
                ConversionFlow &resumed,
                AsyncConversionResourceBatchResult result) mutable {
              if (self->handleAsyncFetchTerminal(
                      resumed, result.terminal_failure))
                return;
              for (const ResolvedConversionResource &resource :
                   result.resources) {
                if (self->handleAsyncFetchTerminal(resumed,
                                                   resource.failure))
                  return;
              }
              if (!self->chargeResolvedResources(result)) {
                self->finishWorkingCapacity(resumed);
                return;
              }
              std::string error;
              if (!self->collectResolvedImports(result, sources, error)) {
                self->response_.status_code = 400;
                self->finishRawBody(resumed, std::move(error));
                return;
              }
              self->ensureImportClosure(resumed);
            }))
      throw std::runtime_error("failed to resolve subscription imports");
  }

  void ensureImportClosure(ConversionFlow &flow) {
    missing_imports_.clear();
    std::vector<UnresolvedImportSource> frontier = planned_imports_;
    for (size_t index = 0; index < frontier.size(); ++index) {
      const UnresolvedImportSource &source = frontier[index];
      const auto resolved = resolved_imports_.find(
          resolvedImportKey(source.path, source.context));
      if (resolved == resolved_imports_.end()) {
        missing_imports_.push_back(source);
        continue;
      }
      std::string normalized =
          replaceAllDistinct(resolved->second, "\r\n", "\n");
      normalized = replaceAllDistinct(normalized, "\r", "\n");
      for (const std::string &line : split(normalized, "\n")) {
        const std::string item = regTrim(line);
        if (item.empty() || startsWith(item, "#") ||
            startsWith(item, ";") || startsWith(item, "//"))
          continue;
        const size_t marker = item.find("!!import:");
        const size_t colon = item.find(':');
        if (marker == std::string::npos || colon == std::string::npos ||
            colon + 1 >= item.size())
          continue;
        UnresolvedImportSource nested{item.substr(colon + 1),
                                      source.context};
        if (std::find_if(frontier.begin(), frontier.end(),
                         [&](const UnresolvedImportSource &candidate) {
                           return candidate.path == nested.path &&
                                  candidate.context == nested.context;
                         }) == frontier.end())
          frontier.emplace_back(std::move(nested));
      }
    }
    planned_imports_ = std::move(frontier);
    if (settings_->maxAllowedRulesets != 0 &&
        planned_imports_.size() > settings_->maxAllowedRulesets) {
      response_.status_code = 400;
      finishRawBody(flow,
                    "Invalid request: subscription import fan-out exceeds "
                    "the configured resource limit.\n"
                    "无效请求：订阅导入扇出数量超过配置的资源限制。");
      return;
    }
    if (!missing_imports_.empty()) {
      resolveMissingImports(flow);
      return;
    }
    // A previous discovery pass may have partially populated node/generator
    // state before an unexpected import was reported. Rebuild only the
    // attempt-local parse state; resolved dependencies/import payloads remain.
    rebuildPolicy();
    beginSubscriptionPlanning(flow);
  }

  void releaseResolvedDependencyPayloads() {
    resolved_dependencies_ = {};
    dependency_requests_.clear();
  }

  uint64_t remainingWorkingBytes() const noexcept {
    return working_reservation_bytes_ > working_source_charge_bytes_
               ? working_reservation_bytes_ -
                     working_source_charge_bytes_
               : 0;
  }

  size_t remainingWorkingSizeBytes() const noexcept {
    return static_cast<size_t>(std::min<uint64_t>(
        remainingWorkingBytes(), std::numeric_limits<size_t>::max()));
  }

  size_t remainingOutputBytes() const noexcept {
    // BoundedOutputSink uses an allocator-capped staging string and preserves
    // the existing std::string generator API with one final copy. Give each
    // side half of the remaining request envelope so both buffers can coexist
    // during that ABI conversion without exceeding the reservation.
    return remainingWorkingSizeBytes() / 2;
  }

  bool prepareGenerationWorkingBudget() noexcept {
    if (generation_structure_charge_bytes_ != 0)
      return true;
    const std::string *base =
        fetch_plan_ && !fetch_plan_->base_path.empty()
            ? &resolved_base_content_
            : nullptr;
    const uint64_t estimate = forceMaxGenerationWorkingEstimate(
        subscription_->nodes, policy_->custom_proxy_groups,
        fetch_plan_->ruleset_content, base, policy_->generator.nodelist);
    const uint64_t structural_partition = remainingWorkingBytes() / 2;
    uint64_t script_native_limit = 0;
    bool group_script = false;
    if (policy_->generator.authorized) {
      for (const ProxyGroupConfig &group : policy_->custom_proxy_groups) {
        if (std::any_of(group.Proxies.begin(), group.Proxies.end(),
                        [](const std::string &rule) {
                          return startsWith(rule, "script:");
                        })) {
          group_script = true;
          break;
        }
      }
    }
    if (group_script && estimate < structural_partition) {
      const ResourceControlSnapshot resources = resourceControlSnapshot();
      script_native_limit = std::min<uint64_t>(
          resources.calculated_force_max_budget
              .quickjs_heap_bytes_per_worker,
          structural_partition - estimate);
    }
    uint64_t total_estimate = estimate;
    if (script_native_limit > UINT64_MAX - total_estimate)
      total_estimate = UINT64_MAX;
    else
      total_estimate += script_native_limit;
    if (estimate == UINT64_MAX || total_estimate > structural_partition ||
        (group_script && script_native_limit == 0) ||
        !chargeWorkingBytes(total_estimate)) {
      working_capacity_exceeded_ = true;
      return false;
    }
    policy_->generator.force_max_group_script_limited = group_script;
    policy_->generator.force_max_group_script_remaining_bytes =
        static_cast<size_t>(std::min<uint64_t>(
            script_native_limit, std::numeric_limits<size_t>::max()));
    generation_structure_charge_bytes_ = total_estimate;
    return true;
  }

  bool chargeWorkingBytes(uint64_t bytes,
                          uint64_t expansion = 1) noexcept {
    uint64_t charge = 0;
    if ((bytes != 0 && expansion > UINT64_MAX / bytes) ||
        (charge = bytes * expansion) > remainingWorkingBytes()) {
      working_capacity_exceeded_ = true;
      return false;
    }
    working_source_charge_bytes_ += charge;
    return true;
  }

  void finishWorkingCapacity(ConversionFlow &flow) {
    if (request_.context)
      request_.context->suggestFailure(
          RequestFailureAttribution::Capacity);
    response_.status_code = 503;
    response_.content_type = "text/plain; charset=utf-8";
    response_.headers = {{"Cache-Control", "private, no-store"},
                         {"Retry-After", "1"}};
    finishRawBody(
        flow,
        "Service temporarily unavailable: conversion working set exceeds "
        "the reserved memory envelope.\n"
        "服务暂时不可用：转换工作集超出已预留的内存包络。\n");
  }

  bool chargeResolvedResources(
      const AsyncConversionResourceBatchResult &result) noexcept {
    for (const ResolvedConversionResource &resource : result.resources) {
      if (resource.payload &&
          !chargeWorkingBytes(resource.payload->content.size(), 4))
        return false;
    }
    return true;
  }

  bool chargeResolvedSubscriptions(
      const AsyncSubscriptionBatchResult &result) noexcept {
    for (const AsyncSubscriptionSlot &slot : result.slots) {
      if (slot.payload &&
          !chargeWorkingBytes(slot.payload->content.size(), 4))
        return false;
    }
    return true;
  }

  bool requiresQuickJsLane() const {
#ifdef NO_JS_RUNTIME
    return false;
#else
    if (!parsed_ || !policy_)
      return false;
    const extra_settings &generator = policy_->generator;
    if (!settings_->filterScript.empty())
      return true;
    if (generator.authorized && generator.sort_flag &&
        !generator.sort_script.empty())
      return true;
    if (generator.authorized) {
      const auto scripted_match = [](const RegexMatchConfigs &entries) {
        return std::any_of(
            entries.begin(), entries.end(),
            [](const RegexMatchConfig &entry) {
              return !entry.Script.empty();
            });
      };
      if (scripted_match(generator.rename_array) ||
          scripted_match(generator.emoji_array))
        return true;
      for (const ProxyGroupConfig &group : policy_->custom_proxy_groups)
        if (std::any_of(group.Proxies.begin(), group.Proxies.end(),
                        [](const std::string &rule) {
                          return startsWith(regTrim(rule), "script:");
                        }))
          return true;
      if (parsed_->url.find("script:") != std::string::npos ||
          (parsed_->enable_insert.get(false) &&
           settings_->insertUrls.find("script:") != std::string::npos))
        return true;
      for (const auto &[_, content] : resolved_imports_)
        if (content.find("script:") != std::string::npos)
          return true;
    }
    return false;
#endif
  }

#ifndef NO_JS_RUNTIME
  void executeQuickJsPass(qjs::Context &context,
                          bool resolved_subscriptions) {
    (void)resolved_subscriptions;
    Settings lane_settings = *settings_;
    SettingsSnapshot lane_snapshot =
        std::make_shared<const Settings>(std::move(lane_settings));
    ScopedSettingsView lane_view(lane_snapshot);
    extra_settings &generator = policy_->generator;
    generator.js_runtime = nullptr;
    generator.js_context = &context;
    try {
      missing_subscriptions_.clear();
      missing_imports_.clear();
      SubscriptionResolutionView resolution;
      // Script links can compute their source URL dynamically. Execute the
      // whole script-bearing parse/generate transaction once on this bounded
      // lane; any synchronous source wait is isolated here and never occupies
      // a main compute worker. Re-entering the lane would replay arbitrary
      // script side effects, so this pass is deliberately non-resumable.
      resolution.require_resolved = false;
      resolution.missing = nullptr;
      resolution.resolved_imports = &resolved_imports_;
      resolution.missing_imports = &missing_imports_;
      quickjs_stage_ = processSubscriptionNodes(
          request_, response_, *lane_snapshot, *parsed_, *policy_,
          *subscription_, &resolution);
      quickjs_generated_ = false;
      if (!missing_imports_.empty() || quickjs_stage_.complete) {
        generator.js_context = nullptr;
        return;
      }
      pending_uploads_.clear();
      if (!prepareGenerationWorkingBudget()) {
        quickjs_capacity_exceeded_ = true;
        generator.js_context = nullptr;
        return;
      }
      try {
        const SubStageResponse generated = dispatchTargetGenerator(
            request_, response_, *lane_snapshot, *parsed_, *policy_,
            *fetch_plan_, *subscription_, *generation_,
            fetch_plan_->base_path.empty() ? nullptr
                                           : &resolved_base_content_,
            &pending_uploads_, remainingOutputBytes());
        quickjs_stage_ = generated;
        if (generated.complete) {
          generator.js_context = nullptr;
          return;
        }
        quickjs_body_ = assembleSubResponse(
            request_, response_, *lane_snapshot, *parsed_, *policy_,
            *fetch_plan_, *generation_, remainingOutputBytes());
        quickjs_generated_ = true;
      } catch (const BoundedOutputExceeded &) {
        quickjs_capacity_exceeded_ = true;
      }
      generator.js_context = nullptr;
    } catch (...) {
      generator.js_context = nullptr;
      throw;
    }
  }

  void startQuickJsPass(ConversionFlow &flow,
                        bool resolved_subscriptions) {
    QuickJsLane *lane = globalQuickJsLane();
    if (!lane)
      throw std::runtime_error("force max QuickJS lane unavailable");
    QuickJsTaskOptions options;
    options.bytes = request_.context->estimatedBytes();
    options.deadline = request_.context->deadline();
    options.settings = settings_;
    options.request_context = request_.context;
    quickjs_stage_ = {};
    quickjs_body_.clear();
    quickjs_generated_ = false;
    quickjs_capacity_exceeded_ = false;
    auto self = shared_from_this();
    if (!runQuickJsOnFlow(
            flow, *lane, std::move(options),
            [self, resolved_subscriptions](qjs::Context &context) {
              self->executeQuickJsPass(context,
                                       resolved_subscriptions);
            },
            [self, resolved_subscriptions](
                ConversionFlow &resumed,
                QuickJsTaskResult result) mutable {
              self->quickJsPassReady(resumed, result,
                                     resolved_subscriptions);
            }))
      throw std::runtime_error("failed to submit force max QuickJS pass");
  }

  void quickJsPassReady(ConversionFlow &flow, QuickJsTaskResult result,
                        bool resolved_subscriptions) {
    (void)resolved_subscriptions;
    if (result.status != QuickJsTaskStatus::Success) {
      if (result.status == QuickJsTaskStatus::Capacity) {
        working_capacity_exceeded_ = true;
        finishWorkingCapacity(flow);
        return;
      }
      if (result.status == QuickJsTaskStatus::Cancelled ||
          result.status == QuickJsTaskStatus::Deadline ||
          result.status == QuickJsTaskStatus::Shutdown) {
        flow.requestCancellation(
            result.status == QuickJsTaskStatus::Deadline
                ? RequestCancellationReason::Deadline
                : (result.status == QuickJsTaskStatus::Shutdown
                       ? RequestCancellationReason::Shutdown
                       : RequestCancellationReason::ClientDisconnected));
        return;
      }
      throw std::runtime_error("force max QuickJS pass failed");
    }
    if (!missing_imports_.empty())
      throw std::runtime_error(
          "QuickJS transaction discovered an unresolved import");
    if (quickjs_capacity_exceeded_) {
      working_capacity_exceeded_ = true;
      finishWorkingCapacity(flow);
      return;
    }
    if (quickjs_stage_.complete) {
      finishRawBody(flow, std::move(quickjs_stage_.body));
      return;
    }
    if (!quickjs_generated_)
      throw std::runtime_error("force max QuickJS pass made no progress");
    if (flow.snapshot().phase != ConversionFlowPhase::Parsing &&
        !flow.setPhase(ConversionFlowPhase::Parsing))
      throw std::runtime_error("failed to enter QuickJS parse phase");
    if (!flow.setPhase(ConversionFlowPhase::Generating))
      throw std::runtime_error("failed to enter QuickJS generation phase");
    finishGeneratedBody(flow, std::move(quickjs_body_));
  }
#endif

  void parse(ConversionFlow &flow) {
    try {
      parsed_ = std::make_unique<ParsedSubRequest>();
      policy_ = std::make_unique<EffectiveSubPolicy>();
      fetch_plan_ = std::make_unique<ExternalConfigFetchPlan>();
      subscription_ = std::make_unique<SubscriptionNodeState>();
      generation_ = std::make_unique<TargetGenerationState>();
      response_ = {};
      {
        RequestStageTimer timer(request_.context, RequestStage::Parse);
        std::string error = parseSubRequestArguments(
            request_, response_, *settings_, *parsed_);
        if (!error.empty()) {
          finishRawBody(flow, std::move(error));
          return;
        }
        error = buildEffectiveSubPolicy(
            request_, response_, *settings_,
            track_statistics_ ? &rule_stats_ : nullptr,
            *parsed_, *policy_);
        if (!error.empty()) {
          finishRawBody(flow, std::move(error));
          return;
        }
      }
      template_local_base_ =
          policy_->template_arguments.local_vars;
      buildConfigCandidates();
      if (config_candidates_.empty()) {
        failExternalConfig(flow);
        return;
      }
      if (!flow.setPhase(
              ConversionFlowPhase::FetchingExternalConfig)) {
        throw std::runtime_error("failed to enter external config phase");
      }
      loadNextConfig(flow);
    } catch (...) {
      failOrCancel(flow, std::current_exception());
    }
  }

  void buildConfigCandidates() {
    config_candidates_.clear();
    const bool requested = !parsed_->external_config.empty();
    if (requested) {
      config_candidates_.push_back(
          {parsed_->external_config, FetchContext::PublicRequest, false});
      if (settings_->fallbackToDefaultExternalConfig &&
          !settings_->defaultExtConfig.empty() &&
          settings_->defaultExtConfig != parsed_->external_config)
        config_candidates_.push_back(
            {settings_->defaultExtConfig,
             FetchContext::TrustedConfig, true});
    } else if (!settings_->defaultExtConfig.empty()) {
      config_candidates_.push_back(
          {settings_->defaultExtConfig,
           FetchContext::TrustedConfig, false});
    }
    config_candidate_index_ = 0;
  }

  void loadNextConfig(ConversionFlow &flow) {
    if (config_candidate_index_ >= config_candidates_.size()) {
      failExternalConfig(flow);
      return;
    }
    const ConfigCandidate candidate =
        config_candidates_[config_candidate_index_++];
    template_args arguments = policy_->template_arguments;
    arguments.local_vars = template_local_base_;
    writeLog(candidate.fallback ? LOG_LEVEL_WARNING : LOG_LEVEL_INFO,
             candidate.fallback
                 ? "用户外部配置失败，显式尝试默认外部配置：" +
                       summarizeUrlForLog(candidate.path)
                 : "正在异步加载外部配置：" +
                       summarizeUrlForLog(candidate.path));
    auto self = shared_from_this();
    const bool started = resolveExternalConfigOnFlow(
        flow, candidate.path, candidate.context, settings_,
        request_.context, std::move(arguments),
        [self, candidate](ConversionFlow &resumed,
                          AsyncExternalConfigResult result) mutable {
          self->externalConfigReady(resumed, candidate,
                                    std::move(result));
        }, std::max<uint64_t>(1, remainingWorkingBytes() / 4));
    if (!started)
      throw std::runtime_error("failed to start external config fetch");
  }

  void externalConfigReady(ConversionFlow &flow,
                           const ConfigCandidate &candidate,
                           AsyncExternalConfigResult result) {
    try {
      if (handleExternalConfigTerminal(flow, result.status))
        return;
      const bool loaded =
          result.status == ExternalConfigLoadStatus::Success;
      const bool effective =
          loaded && hasEffectiveExternalConfig(
                        result.config, result.template_arguments,
                        template_local_base_, parsed_->target);
      const bool base_valid =
          effective && validateSelectedExternalBase(
                           result.config, parsed_->target,
                           parsed_->simple_subscription,
                           policy_->generator.nodelist,
                           candidate.context);
      if (!loaded || !effective || !base_valid) {
        writeLog(LOG_LEVEL_WARNING,
                 "异步外部配置不可用，继续候选：status=" +
                     std::to_string(static_cast<int>(result.status)) +
                     " effective=" +
                     std::string(effective ? "true" : "false") +
                     " base_valid=" +
                     std::string(base_valid ? "true" : "false"));
        loadNextConfig(flow);
        return;
      }
      if (!chargeWorkingBytes(result.working_source_bytes, 4)) {
        finishWorkingCapacity(flow);
        return;
      }
      selected_config_.emplace();
      selected_config_->config = std::move(result.config);
      selected_config_->template_arguments =
          std::move(result.template_arguments);
      selected_config_->context = candidate.context;
      selected_config_->fallback = candidate.fallback;
      preparePlan(flow);
    } catch (...) {
      failOrCancel(flow, std::current_exception());
    }
  }

  void failExternalConfig(ConversionFlow &flow) {
    response_.status_code = parsed_ && !parsed_->external_config.empty()
                                ? 400
                                : 500;
    response_.content_type = "text/plain; charset=utf-8";
    response_.headers["Cache-Control"] = "private, no-store";
    finishRawBody(
        flow,
        response_.status_code == 400
            ? "Invalid request: selected external configuration could not "
              "be loaded or applied.\n"
              "无效请求：无法加载或应用用户选择的外部配置。"
            : "Server configuration error: default external configuration "
              "could not be loaded or applied.\n"
              "服务器配置错误：无法加载或应用默认外部配置。");
  }

  void preparePlan(ConversionFlow &flow) {
    try {
      dependency_requests_.clear();
      ConversionDependencyResolution planning;
      planning.requests = &dependency_requests_;
      {
        RequestStageTimer timer(request_.context, RequestStage::Rules);
        std::string error = buildExternalConfigFetchPlan(
            response_, *settings_, *parsed_, *policy_, *fetch_plan_,
            &*selected_config_, &planning);
        if (!error.empty()) {
          finishRawBody(flow, std::move(error));
          return;
        }
      }
      planRequestImports();
      if (!flow.setPhase(ConversionFlowPhase::FetchingRulesets))
        throw std::runtime_error("failed to enter dependency phase");
      if (dependency_requests_.empty()) {
        dependenciesReady(flow, {});
        return;
      }
      auto self = shared_from_this();
      if (!resolveConversionResourcesOnFlow(
              flow, dependency_requests_, settings_, request_.context,
              [self](ConversionFlow &resumed,
                     AsyncConversionResourceBatchResult result) mutable {
                self->dependenciesReady(resumed, std::move(result));
              }))
        throw std::runtime_error("failed to start conversion dependencies");
    } catch (...) {
      failOrCancel(flow, std::current_exception());
    }
  }

  void dependenciesReady(ConversionFlow &flow,
                          AsyncConversionResourceBatchResult result) {
    try {
      if (handleAsyncFetchTerminal(flow, result.terminal_failure))
        return;
      for (const ResolvedConversionResource &resource : result.resources) {
        if (handleAsyncFetchTerminal(flow, resource.failure))
          return;
      }
      if (!chargeResolvedResources(result)) {
        finishWorkingCapacity(flow);
        return;
      }
      resolved_dependencies_ = std::move(result);
      std::string import_error;
      if (!collectResolvedImports(resolved_dependencies_, planned_imports_,
                                  import_error)) {
        response_.status_code = 400;
        finishRawBody(flow, std::move(import_error));
        return;
      }
      rebuildPolicy();
      prepareTargetTemplateArguments(*parsed_, *policy_);
      if (!fetch_plan_->base_path.empty()) {
        auto self = shared_from_this();
        if (!renderTemplateOnFlow(
                flow, fetch_plan_->resolved_base_content,
                policy_->template_arguments, settings_->templatePath,
                fetch_plan_->base_fetch_context, settings_,
                request_.context,
                [self](ConversionFlow &resumed,
                       AsyncTemplateResult rendered) mutable {
                  self->baseReady(resumed, std::move(rendered));
                }, remainingWorkingBytes()))
          throw std::runtime_error("failed to start base template render");
        return;
      }
      ensureImportClosure(flow);
    } catch (...) {
      failOrCancel(flow, std::current_exception());
    }
  }

  void baseReady(ConversionFlow &flow, AsyncTemplateResult rendered) {
    try {
      if (handleTemplateTerminal(flow, rendered.status))
        return;
      if (rendered.status == AsyncTemplateStatus::RenderFailed ||
          rendered.status == AsyncTemplateStatus::FetchFailed) {
        response_.status_code = 400;
        if (rendered.output.empty())
          rendered.output =
              "Invalid template: rendering failed.\n"
              "无效模板：模板渲染失败。\n"
              "Please check the template syntax and configured resources.\n"
              "请检查模板语法和已配置资源。";
        finishRawBody(flow, std::move(rendered.output));
        return;
      }
      if (!chargeWorkingBytes(rendered.output.size())) {
        finishWorkingCapacity(flow);
        return;
      }
      resolved_base_content_ = std::move(rendered.output);
      ensureImportClosure(flow);
    } catch (...) {
      failOrCancel(flow, std::current_exception());
    }
  }

  void beginSubscriptionPlanning(ConversionFlow &flow) {
    try {
      if (!flow.setPhase(ConversionFlowPhase::FetchingSubscriptions))
        throw std::runtime_error("failed to enter subscription phase");
      missing_subscriptions_.clear();
      SubscriptionResolutionView planning;
      planning.missing = &missing_subscriptions_;
      missing_imports_.clear();
      planning.resolved_imports = &resolved_imports_;
      planning.missing_imports = &missing_imports_;
      planning.require_resolved = true;
#ifndef NO_JS_RUNTIME
      if (requiresQuickJsLane()) {
        releaseResolvedDependencyPayloads();
        startQuickJsPass(flow, false);
        return;
      }
#endif
      const SubStageResponse planned = processSubscriptionNodes(
          request_, response_, *settings_, *parsed_, *policy_,
          *subscription_, &planning);
      if (!missing_imports_.empty()) {
        resolveMissingImports(flow);
        return;
      }
      if (missing_subscriptions_.empty()) {
        releaseResolvedDependencyPayloads();
        if (planned.complete) {
          finishRawBody(flow, planned.body);
          return;
        }
        generate(flow);
        return;
      }
      fetchSubscriptions(flow);
    } catch (...) {
      failOrCancel(flow, std::current_exception());
    }
  }

  static bool sameSource(const UnresolvedSubscriptionSource &left,
                         const UnresolvedSubscriptionSource &right) {
    return left.url == right.url && left.context == right.context &&
           left.request_headers == right.request_headers;
  }

  void fetchSubscriptions(ConversionFlow &flow) {
    resolved_keys_.clear();
    for (UnresolvedSubscriptionSource &source : missing_subscriptions_) {
      if (std::find_if(resolved_keys_.begin(), resolved_keys_.end(),
                       [&](const UnresolvedSubscriptionSource &current) {
                         return sameSource(current, source);
                       }) == resolved_keys_.end())
        resolved_keys_.push_back(std::move(source));
    }
    if (settings_->maxAllowedRulesets != 0 &&
        resolved_keys_.size() > settings_->maxAllowedRulesets) {
      response_.status_code = 400;
      finishRawBody(flow,
                 "Invalid request: subscription fan-out exceeds the "
                 "configured resource limit.\n"
                 "无效请求：订阅扇出数量超过配置的资源限制。\n");
      return;
    }
    std::vector<AsyncSubscriptionRequest> requests;
    requests.reserve(resolved_keys_.size());
    for (size_t index = 0; index < resolved_keys_.size(); ++index) {
      const UnresolvedSubscriptionSource &source = resolved_keys_[index];
      AsyncSubscriptionRequest request;
      request.source_index = index;
      request.url = source.url;
      request.proxy = policy_->subscription_proxy;
      request.request_headers = source.request_headers;
      request.cache_ttl = static_cast<unsigned int>(
          std::max(0, settings_->cacheSubscription));
      request.context = source.context;
      requests.emplace_back(std::move(request));
    }
    auto self = shared_from_this();
    if (!resolveSubscriptionsOnFlow(
            flow, std::move(requests), settings_, request_.context,
            [self](ConversionFlow &resumed,
                   AsyncSubscriptionBatchResult result) mutable {
              self->subscriptionsReady(resumed, std::move(result));
            }))
      throw std::runtime_error("failed to start subscription fan-out");
  }

  void rebuildPolicy() {
    response_ = {};
    parsed_ = std::make_unique<ParsedSubRequest>();
    policy_ = std::make_unique<EffectiveSubPolicy>();
    fetch_plan_ = std::make_unique<ExternalConfigFetchPlan>();
    subscription_ = std::make_unique<SubscriptionNodeState>();
    generation_ = std::make_unique<TargetGenerationState>();
    std::string error = parseSubRequestArguments(
        request_, response_, *settings_, *parsed_);
    if (!error.empty())
      throw std::runtime_error("force max flow reparse failed");
    error = buildEffectiveSubPolicy(
        request_, response_, *settings_,
        track_statistics_ ? &rule_stats_ : nullptr,
        *parsed_, *policy_);
    if (!error.empty())
      throw std::runtime_error("force max flow policy rebuild failed");
    ConversionDependencyResolution resolved;
    resolved.resolved = &resolved_dependencies_;
    error = buildExternalConfigFetchPlan(
        response_, *settings_, *parsed_, *policy_, *fetch_plan_,
        &*selected_config_, &resolved);
    if (!error.empty())
      throw std::runtime_error("force max flow config rebuild failed");
  }

  bool lookupSubscription(
      const std::string &url, FetchContext context,
      const string_icase_map &headers, std::string &content,
      std::string &response_headers) const {
    for (size_t index = 0;
         index < resolved_keys_.size() &&
         index < resolved_subscriptions_.slots.size(); ++index) {
      const UnresolvedSubscriptionSource &key = resolved_keys_[index];
      if (key.url != url || key.context != context ||
          key.request_headers != headers)
        continue;
      const AsyncSubscriptionSlot &slot =
          resolved_subscriptions_.slots[index];
      if (slot.payload && slot.failure == AsyncFetchFailure::None) {
        content = slot.payload->content;
        response_headers = slot.payload->response_headers;
      } else {
        content.clear();
        response_headers.clear();
      }
      return true;
    }
    return false;
  }

  void subscriptionsReady(ConversionFlow &flow,
                           AsyncSubscriptionBatchResult result) {
    try {
      if (handleAsyncFetchTerminal(flow, result.terminal_failure))
        return;
      for (const AsyncSubscriptionSlot &slot : result.slots) {
        if (handleAsyncFetchTerminal(flow, slot.failure))
          return;
      }
      if (!chargeResolvedSubscriptions(result)) {
        finishWorkingCapacity(flow);
        return;
      }
      resolved_subscriptions_ = std::move(result);
      if (!flow.setPhase(ConversionFlowPhase::Parsing))
        throw std::runtime_error("failed to enter final parse phase");
      rebuildPolicy();
      std::vector<UnresolvedSubscriptionSource> missing;
      SubscriptionResolutionView resolved;
      resolved.require_resolved = true;
      resolved.missing = &missing;
      missing_imports_.clear();
      resolved.resolved_imports = &resolved_imports_;
      resolved.missing_imports = &missing_imports_;
      resolved.lookup =
          [self = shared_from_this()](
              const std::string &url, FetchContext context,
              const string_icase_map &headers, std::string &content,
              std::string &response_headers) {
            return self->lookupSubscription(
                url, context, headers, content, response_headers);
          };
      const SubStageResponse parsed = processSubscriptionNodes(
          request_, response_, *settings_, *parsed_, *policy_,
          *subscription_, &resolved);
      if (!missing_imports_.empty()) {
        resolveMissingImports(flow);
        return;
      }
      if (!missing.empty())
        throw std::runtime_error(
            "resolved subscription set was incomplete");
      releaseResolvedDependencyPayloads();
      resolved_subscriptions_ = {};
      resolved_keys_.clear();
      if (parsed.complete) {
        finishRawBody(flow, parsed.body);
        return;
      }
      generate(flow);
    } catch (...) {
      failOrCancel(flow, std::current_exception());
    }
  }

  void generate(ConversionFlow &flow) {
    try {
      if (flow.snapshot().phase != ConversionFlowPhase::Parsing &&
          !flow.setPhase(ConversionFlowPhase::Parsing))
        throw std::runtime_error("failed to enter parse phase");
      if (!flow.setPhase(ConversionFlowPhase::Generating))
        throw std::runtime_error("failed to enter generation phase");
      RequestStageTimer timer(request_.context, RequestStage::Serialize);
      if (!prepareGenerationWorkingBudget()) {
        finishWorkingCapacity(flow);
        return;
      }
      const SubStageResponse generated = dispatchTargetGenerator(
          request_, response_, *settings_, *parsed_, *policy_,
          *fetch_plan_, *subscription_, *generation_,
          fetch_plan_->base_path.empty() ? nullptr
                                         : &resolved_base_content_,
          &pending_uploads_, remainingOutputBytes());
      if (generated.complete) {
        finishRawBody(flow, generated.body);
        return;
      }
      std::string body = assembleSubResponse(
          request_, response_, *settings_, *parsed_, *policy_,
          *fetch_plan_, *generation_, remainingOutputBytes());
      finishGeneratedBody(flow, std::move(body));
    } catch (const BoundedOutputExceeded &) {
      working_capacity_exceeded_ = true;
      finishWorkingCapacity(flow);
    } catch (...) {
      failOrCancel(flow, std::current_exception());
    }
  }

  bool retrySafe() const {
    if (working_capacity_exceeded_ || retry_attempted_ || !prepared_->coalesce ||
        !settings_->coalesceRetryOn5xx || !parsed_)
      return false;
    if (parsed_->upload.get(false) || requiresQuickJsLane())
      return false;
    // Imported content can legitimately introduce a script source. Avoid a
    // speculative replay even when the initial request text itself is pure.
    if (parsed_->url.find("!!import:") != std::string::npos ||
        settings_->insertUrls.find("!!import:") != std::string::npos)
      return false;
    return true;
  }

  void requestRetry(ConversionFlow &flow, std::string body) {
    first_failure_.emplace();
    first_failure_->response = std::move(response_);
    first_failure_->body = std::move(body);
    first_failure_->rule_conversions = rule_stats_.rules;
    first_failure_->uploads = std::move(pending_uploads_);
    retry_attempted_ = true;
    retry_requested_ = true;
    writeLog(LOG_LEVEL_WARNING,
             "/sub force_max flow 首次转换返回 5xx，正在沿用绝对截止"
             "时间进行一次内部 flow 重试。");
    (void)flow.complete();
  }

  void selectAttemptBody(ConversionFlow &flow, std::string body) {
    if (response_.status_code >= 500 && retrySafe()) {
      if (!chargeWorkingBytes(body.capacity())) {
        working_capacity_exceeded_ = true;
      } else {
        first_failure_charge_bytes_ = body.capacity();
        requestRetry(flow, std::move(body));
        return;
      }
    }
    if (response_.status_code >= 500 && !retry_attempted_) {
      writeLog(LOG_LEVEL_INFO,
               "FORCE_MAX_RETRY_SKIPPED coalesce=" +
                   std::string(prepared_->coalesce ? "true" : "false") +
                   " enabled=" +
                   std::string(settings_->coalesceRetryOn5xx ? "true"
                                                             : "false") +
                   " upload=" +
                   std::string(parsed_ && parsed_->upload.get(false)
                                   ? "true" : "false") +
                   " quickjs=" +
                   std::string(parsed_ && requiresQuickJsLane()
                                   ? "true" : "false") +
                   " import=" +
                   std::string(parsed_ &&
                                       (parsed_->url.find("!!import:") !=
                                            std::string::npos ||
                                        settings_->insertUrls.find(
                                            "!!import:") !=
                                            std::string::npos)
                                   ? "true" : "false"));
    }
    if (retry_attempted_ && response_.status_code >= 500 &&
        first_failure_) {
      response_ = std::move(first_failure_->response);
      body = std::move(first_failure_->body);
      rule_stats_.rules = first_failure_->rule_conversions;
      pending_uploads_ = std::move(first_failure_->uploads);
    }
    first_failure_.reset();
    if (first_failure_charge_bytes_ != 0) {
      working_source_charge_bytes_ -= std::min(
          working_source_charge_bytes_, first_failure_charge_bytes_);
      first_failure_charge_bytes_ = 0;
    }
    if (working_reservation_bytes_ != 0 &&
        body.capacity() > remainingWorkingBytes()) {
      working_capacity_exceeded_ = true;
      if (request_.context)
        request_.context->suggestFailure(
            RequestFailureAttribution::Capacity);
      response_.status_code = 503;
      response_.content_type = "text/plain; charset=utf-8";
      response_.headers = {{"Cache-Control", "private, no-store"},
                           {"Retry-After", "1"}};
      pending_uploads_.clear();
      body = "Service temporarily unavailable: generated response exceeds "
             "the reserved working-memory envelope.\n"
             "服务暂时不可用：生成结果超出已预留的工作内存包络。\n";
    }
    selected_body_ = std::move(body);
    upload_index_ = 0;
    if (pending_uploads_.empty()) {
      publishSelectedBody(flow);
      return;
    }
    if (!flow.setPhase(ConversionFlowPhase::Uploading))
      throw std::runtime_error("failed to enter upload phase");
    uploadNext(flow);
  }

  void finishRawBody(ConversionFlow &flow, std::string body) {
    pending_uploads_.clear();
    selectAttemptBody(flow, std::move(body));
  }

  void finishGeneratedBody(ConversionFlow &flow, std::string body) {
    selectAttemptBody(flow, std::move(body));
  }

  void uploadNext(ConversionFlow &flow) {
    if (upload_index_ >= pending_uploads_.size()) {
      if (upload_failed_)
        writeLog(LOG_LEVEL_WARNING,
                 "GIST_OPTIONAL_UPLOAD_FAILED "
                 "action=return-conversion-result");
      publishSelectedBody(flow);
      return;
    }
    const PendingUpload &pending = pending_uploads_[upload_index_];
    auto self = shared_from_this();
    if (!uploadGistOnFlow(
            flow, pending.name, pending.path, selected_body_,
            pending.write_manage_url, settings_, request_.context,
            [self](ConversionFlow &resumed,
                   AsyncUploadResult result) mutable {
              if (result.status != AsyncUploadStatus::Success)
                self->upload_failed_ = true;
              ++self->upload_index_;
              self->uploadNext(resumed);
            }))
      throw std::runtime_error("failed to start optional Gist upload");
  }

  void publishSelectedBody(ConversionFlow &flow) {
    if (finalized_)
      throw std::runtime_error("force max response finalized twice");
    finalized_ = true;
    std::string body;
    try {
      body = finalizeSubResponse(request_, response_, std::move(selected_body_),
                                 prepared_->age,
                                 remainingWorkingSizeBytes());
    } catch (const BoundedOutputExceeded &) {
      working_capacity_exceeded_ = true;
      if (request_.context)
        request_.context->suggestFailure(
            RequestFailureAttribution::Capacity);
      response_.status_code = 503;
      response_.content_type = "text/plain; charset=utf-8";
      response_.headers = {{"Cache-Control", "private, no-store"},
                           {"Retry-After", "1"}};
      body = "Service temporarily unavailable: finalized response exceeds "
             "the reserved working-memory envelope.\n"
             "服务暂时不可用：最终响应超出已预留的工作内存包络。\n";
    }
    response_.shared_body = tryMakeRetainedResponseBody(std::move(body));
    if (!response_.shared_body) {
      working_capacity_exceeded_ = true;
      if (request_.context)
        request_.context->setFinalFailureAttribution(
            RequestFailureAttribution::Capacity);
      response_.status_code = 503;
      response_.content_type = "text/plain; charset=utf-8";
      response_.headers = {{"Cache-Control", "private, no-store"},
                           {"Retry-After", "1"}};
      body = "Service temporarily unavailable: retained response byte "
             "capacity is full.\n"
             "服务暂时不可用：响应字节容量已满。\n";
    } else {
      body.clear();
    }
    if (record_direct_statistics_)
      recordTrackedSubRequest(track_statistics_, request_, response_,
                              rule_stats_.rules);
    output_.response = std::move(response_);
    output_.body = std::move(body);
    output_.rule_conversions = rule_stats_.rules;
    output_.capacity_rejected = working_capacity_exceeded_;
    if (flow.snapshot().phase != ConversionFlowPhase::Publishing)
      (void)flow.setPhase(ConversionFlowPhase::Publishing);
    (void)flow.complete();
  }

  void terminal(ConversionFlowTerminal terminal) noexcept {
    terminal_deliveries_.fetch_add(1, std::memory_order_acq_rel);
    if (terminal.state == ConversionFlowTerminalState::Failed &&
        terminal.error) {
      try {
        std::rethrow_exception(terminal.error);
      } catch (const std::exception &error) {
        writeLog(LOG_LEVEL_ERROR,
                 "FORCE_MAX_FLOW_FAILED detail=" +
                     summarizeSensitiveTextForLog(error.what()));
      } catch (...) {
        writeLog(LOG_LEVEL_ERROR,
                 "FORCE_MAX_FLOW_FAILED detail=unknown");
      }
    }
    flow_.reset();
    if (retry_requested_ &&
        terminal.state == ConversionFlowTerminalState::Completed) {
      retry_requested_ = false;
      resetAttemptState();
      if (startAttempt())
        return;
      terminal = {ConversionFlowTerminalState::Capacity,
                  RequestCancellationReason::None,
                  std::make_exception_ptr(std::runtime_error(
                      "force max retry flow could not start"))};
    }
    ForceMaxFlowCompletion completion = std::move(completion_);
    if (!completion)
      return;
    try {
      completion(std::move(output_), std::move(terminal));
    } catch (...) {
    }
  }

  Request request_;
  const std::shared_ptr<const PreparedSubRequest> prepared_;
  const SettingsSnapshot settings_;
  const bool track_statistics_;
  const bool record_direct_statistics_;
  ForceMaxFlowCompletion completion_;
  std::shared_ptr<ConversionFlow> flow_;
  std::unique_ptr<ParsedSubRequest> parsed_;
  std::unique_ptr<EffectiveSubPolicy> policy_;
  std::unique_ptr<ExternalConfigFetchPlan> fetch_plan_;
  std::unique_ptr<SubscriptionNodeState> subscription_;
  std::unique_ptr<TargetGenerationState> generation_;
  Response response_;
  RuleConversionStats rule_stats_;
  string_map template_local_base_;
  std::vector<ConfigCandidate> config_candidates_;
  size_t config_candidate_index_ = 0;
  std::optional<ResolvedExternalConfigSelection> selected_config_;
  std::vector<UnresolvedSubscriptionSource> missing_subscriptions_;
  std::vector<UnresolvedSubscriptionSource> resolved_keys_;
  AsyncSubscriptionBatchResult resolved_subscriptions_;
  std::vector<AsyncConversionResourceRequest> dependency_requests_;
  AsyncConversionResourceBatchResult resolved_dependencies_;
  std::vector<UnresolvedImportSource> planned_imports_;
  std::vector<UnresolvedImportSource> missing_imports_;
  string_map resolved_imports_;
  unsigned int import_resolution_rounds_ = 0;
  std::string resolved_base_content_;
  std::vector<PendingUpload> pending_uploads_;
  size_t upload_index_ = 0;
  bool upload_failed_ = false;
  std::string selected_body_;
  std::optional<AttemptCandidate> first_failure_;
  bool retry_attempted_ = false;
  bool retry_requested_ = false;
  bool finalized_ = false;
  SubStageResponse quickjs_stage_;
  std::string quickjs_body_;
  bool quickjs_generated_ = false;
  bool quickjs_capacity_exceeded_ = false;
  uint64_t working_reservation_bytes_ = 0;
  uint64_t working_source_charge_bytes_ = 0;
  uint64_t generation_structure_charge_bytes_ = 0;
  uint64_t first_failure_charge_bytes_ = 0;
  bool working_capacity_exceeded_ = false;
  std::atomic<uint64_t> terminal_deliveries_{0};
  ForceMaxFlowOutput output_;
};

static bool startForceMaxFlow(
    Request request, std::shared_ptr<const PreparedSubRequest> prepared,
    bool track_statistics, bool record_direct_statistics,
    ForceMaxFlowCompletion completion) {
  if (!prepared || !completion)
    return false;
  try {
    auto state = std::make_shared<ForceMaxFlowState>(
        std::move(request), std::move(prepared), track_statistics,
        record_direct_statistics, std::move(completion));
    return state->start();
  } catch (const BoundedOutputExceeded &) {
    throw;
  } catch (...) {
    return false;
  }
}

} // namespace

std::string simpleToClashR(RESPONSE_CALLBACK_ARGS) {
  auto argument = joinArguments(request.argument);
  int *status_code = &response.status_code;

  std::string url = argument.size() <= 8 ? "" : argument.substr(8);
  if (url.empty() || argument.substr(0, 8) != "sublink=") {
    *status_code = 400;
    return "Invalid request: missing sublink parameter.\n"
           "无效请求：缺少 sublink 参数。\n"
           "Please call this endpoint as /sub2clashr?sublink=<subscription-url>.\n"
           "请使用 /sub2clashr?sublink=<订阅链接> 调用该接口。";
  }
  if (url == "sublink") {
    *status_code = 400;
    return "Invalid request: the default placeholder was not replaced with a "
           "subscription link.\n"
           "无效请求：默认占位符没有被替换为订阅链接。\n"
           "Please provide a real subscription URL in the sublink parameter.\n"
           "请在 sublink 参数中提供真实订阅链接。";
  }
  request.argument.emplace("target", "clashr");
  request.argument.emplace("url", urlEncode(url));
  return subconverter(request, response);
}

std::string surgeConfToClash(RESPONSE_CALLBACK_ARGS) {
  auto argument = joinArguments(request.argument);
  int *status_code = &response.status_code;

  INIReader ini;
  string_array dummy_str_array;
  std::vector<Proxy> nodes;
  std::string base_content,
      url = argument.size() <= 5 ? "" : argument.substr(5);
  const std::string proxygroup_name = global.clashUseNewField ? "proxy-groups"
                                                              : "Proxy Group",
                    rule_name = global.clashUseNewField ? "rules" : "Rule";

  ini.store_any_line = true;

  if (url.empty())
    url = global.defaultUrls;
  if (url.empty() || argument.substr(0, 5) != "link=") {
    *status_code = 400;
    return "Invalid request: missing link parameter.\n"
           "无效请求：缺少 link 参数。\n"
           "Please call this endpoint as /surge2clash?link=<surge-config-url>.\n"
           "请使用 /surge2clash?link=<Surge配置链接> 调用该接口。";
  }
  if (url == "link") {
    *status_code = 400;
    return "Invalid request: the default placeholder was not replaced with a "
           "Surge configuration link.\n"
           "无效请求：默认占位符没有被替换为 Surge 配置链接。\n"
           "Please provide a real Surge configuration URL in the link "
           "parameter.\n"
           "请在 link 参数中提供真实 Surge 配置链接。";
  }
  writeLog(0, "SurgeConfToClash 调用，URL：'" + url + "'。",
           LOG_LEVEL_INFO);

  ProxyPolicy proxy = parseProxy(global.proxyConfig);
  YAML::Node clash;
  template_args tpl_args;
  tpl_args.global_vars = global.templateVars;
  tpl_args.local_vars["clash.new_field_name"] =
      global.clashUseNewField ? "true" : "false";
  tpl_args.request_params["target"] = "clash";
  tpl_args.request_params["url"] = url;

  if (render_template(fetchFile(global.clashBase, proxy, global.cacheConfig),
                      tpl_args, base_content, global.templatePath) != 0) {
    *status_code = 400;
    return base_content;
  }
  clash = YAML::Load(base_content);

  base_content = fetchFile(url, proxy, global.cacheConfig);

  if (ini.parse(base_content) != INIREADER_EXCEPTION_NONE) {
    const std::string parser_detail = ini.get_last_error();
    const std::string errmsg = "Invalid request: failed to parse Surge "
                               "configuration.\n"
                               "无效请求：Surge 配置解析失败。";
    // std::cerr<<errmsg<<"\n";
    writeLog(0, "Surge 配置解析失败。原因：" + ini.get_last_error(),
             LOG_LEVEL_ERROR);
    *status_code = 400;
    return errmsg;
  }
  if (!ini.section_exist("Proxy") || !ini.section_exist("Proxy Group") ||
      !ini.section_exist("Rule")) {
    std::string errmsg =
        "Invalid request: incomplete Surge configuration.\n"
        "无效请求：Surge 配置不完整。\n"
        "Required sections: [Proxy], [Proxy Group], and [Rule].\n"
        "必须包含以下配置段：[Proxy]、[Proxy Group] 和 [Rule]。";
    // std::cerr<<errmsg<<"\n";
    writeLog(0, "Surge 配置不完整，缺少必需配置段。",
             LOG_LEVEL_ERROR);
    *status_code = 400;
    return errmsg;
  }

  // scan groups first, get potential policy-path
  string_multimap section;
  ini.get_items("Proxy Group", section);
  std::string name, type, content;
  string_array links;
  links.emplace_back(url);
  YAML::Node singlegroup;
  for (auto &x : section) {
    singlegroup.reset();
    name = x.first;
    content = x.second;
    dummy_str_array = split(content, ",");
    if (dummy_str_array.empty())
      continue;
    type = dummy_str_array[0];
    if (!(type == "select" || type == "url-test" || type == "fallback" ||
          type == "load-balance"))
      // remove unsupported types
      continue;
    singlegroup["name"] = name;
    singlegroup["type"] = type;
    for (unsigned int i = 1; i < dummy_str_array.size(); i++) {
      if (startsWith(dummy_str_array[i], "url"))
        singlegroup["url"] =
            trim(dummy_str_array[i].substr(dummy_str_array[i].find('=') + 1));
      else if (startsWith(dummy_str_array[i], "interval"))
        singlegroup["interval"] =
            trim(dummy_str_array[i].substr(dummy_str_array[i].find('=') + 1));
      else if (startsWith(dummy_str_array[i], "policy-path"))
        links.emplace_back(
            trim(dummy_str_array[i].substr(dummy_str_array[i].find('=') + 1)));
      else
        singlegroup["proxies"].push_back(trim(dummy_str_array[i]));
    }
    clash[proxygroup_name].push_back(singlegroup);
  }

  proxy = parseProxy(global.proxySubscription, global.proxyBypass);
  eraseElements(dummy_str_array);

  RegexMatchConfigs dummy_regex_array;
  std::string subInfo;
  parse_settings parse_set;
  parse_set.proxy = &proxy;
  parse_set.exclude_remarks = parse_set.include_remarks = &dummy_str_array;
  parse_set.stream_rules = parse_set.time_rules = &dummy_regex_array;
  parse_set.request_header = &request.headers;
  parse_set.sub_info = &subInfo;
  for (std::string &x : links) {
    // std::cerr<<"Fetching node data from url '"<<x<<"'."<<std::endl;
    writeLog(0, "正在从 URL 获取节点数据：'" + x + "'。", LOG_LEVEL_INFO);
    if (addNodes(x, nodes, 0, parse_set) == -1) {
      if (global.skipFailedLinks)
        writeLog(0,
                 "以下链接不包含任何有效节点信息：" + x,
                 LOG_LEVEL_WARNING);
      else {
        *status_code = 400;
        return "Invalid request: this link does not contain any supported "
               "proxy nodes.\n"
               "无效请求：该链接不包含任何受支持的代理节点。\n"
               "Please check whether the link is reachable and the node URI "
               "format is supported.\n"
               "请检查链接是否可访问，以及节点 URI 格式是否受支持。\n"
               "Link / 链接: " +
               x;
      }
    }
  }

  // exit if found nothing
  if (nodes.empty()) {
    *status_code = 400;
    return "Invalid request: no valid proxy nodes were found in the Surge "
           "configuration or its policy-path subscriptions.\n"
           "无效请求：Surge 配置或其 policy-path 订阅中未找到有效代理节点。\n"
           "Please check whether the source configuration contains supported "
           "proxy entries.\n"
           "请检查源配置中是否包含受支持的代理条目。";
  }

  extra_settings ext;
  ext.sort_flag = global.enableSort;
  ext.filter_deprecated = global.filterDeprecated;
  ext.clash_new_field_name = global.clashUseNewField;
  ext.udp = global.UDPFlag;
  ext.tfo = global.TFOFlag;
  ext.skip_cert_verify = global.skipCertVerify;
  ext.tls13 = global.TLS13Flag;
  ext.clash_proxies_style = global.clashProxiesStyle;

  ProxyGroupConfigs dummy_groups;
  proxyToClash(nodes, clash, dummy_groups, false, ext);

  section.clear();
  ini.get_items("Proxy", section);
  for (auto &x : section) {
    singlegroup.reset();
    name = x.first;
    content = x.second;
    dummy_str_array = split(content, ",");
    if (dummy_str_array.empty())
      continue;
    content = trim(dummy_str_array[0]);
    switch (hash_(content)) {
    case "direct"_hash:
      singlegroup["name"] = name;
      singlegroup["type"] = "select";
      singlegroup["proxies"].push_back("DIRECT");
      break;
    case "reject"_hash:
    case "reject-tinygif"_hash:
      singlegroup["name"] = name;
      singlegroup["type"] = "select";
      singlegroup["proxies"].push_back("REJECT");
      break;
    default:
      continue;
    }
    clash[proxygroup_name].push_back(singlegroup);
  }

  eraseElements(dummy_str_array);
  ini.get_all("Rule", "{NONAME}", dummy_str_array);
  YAML::Node rule;
  string_array strArray;
  std::string strLine;
  std::stringstream ss;
  std::string::size_type lineSize;
  for (std::string &x : dummy_str_array) {
    if (startsWith(x, "RULE-SET")) {
      strArray = split(x, ",");
      if (strArray.size() != 3)
        continue;
      content = webGet(strArray[1], proxy, global.cacheRuleset);
      if (content.empty())
        continue;

      ss << content;
      char delimiter = getLineBreak(content);

      while (getline(ss, strLine, delimiter)) {
        lineSize = strLine.size();
        if (lineSize && strLine[lineSize - 1] == '\r') // remove line break
          strLine.erase(--lineSize);
        if (!lineSize || strLine[0] == ';' || strLine[0] == '#' ||
            (lineSize >= 2 && strLine[0] == '/' &&
             strLine[1] == '/')) // empty lines and comments are ignored
          continue;
        else if (!std::any_of(ClashRuleTypes.begin(), ClashRuleTypes.end(),
                              [&strLine](const std::string &type) {
                                return startsWith(strLine, type);
                              })) // remove unsupported types
          continue;
        strLine = appendClashRuleTarget(strLine, trim(strArray[2]));
        rule.push_back(strLine);
      }
      ss.clear();
      continue;
    } else if (!std::any_of(ClashRuleTypes.begin(), ClashRuleTypes.end(),
                            [&strLine](const std::string &type) {
                              return startsWith(strLine, type);
                            }))
      continue;
    rule.push_back(x);
  }
  clash[rule_name] = rule;

  response.headers["profile-update-interval"] =
      std::to_string(global.updateInterval / 3600);
  writeLog(0, "转换完成。", LOG_LEVEL_INFO);
  return YAML::Dump(clash);
}

std::string getProfile(RESPONSE_CALLBACK_ARGS) {
  auto &argument = request.argument;
  int *status_code = &response.status_code;

  std::string name = getUrlArg(argument, "name"),
              token = getUrlArg(argument, "token");
  string_array profiles = split(name, "|");
  if (token.empty() || profiles.empty()) {
    *status_code = 403;
    return "Forbidden: missing profile name or access token.\n"
           "禁止访问：缺少配置名称或访问令牌。";
  }
  std::string profile_content;
  name = profiles[0];
  /*if(vfs::vfs_exist(name))
  {
      profile_content = vfs::vfs_get(name);
  }
  else */
  if (fileExist(name)) {
    profile_content = fileGet(name, true);
  } else {
    *status_code = 404;
    return "Profile not found: the requested profile does not exist.\n"
           "未找到配置：请求的 profile 不存在。\n"
           "Profile / 配置: " +
           name;
  }
  // std::cerr<<"Trying to load profile '" + name + "'.\n";
  writeLog(0, "正在加载配置档：'" + name + "'。", LOG_LEVEL_INFO);
  INIReader ini;
  if (ini.parse(profile_content) != INIREADER_EXCEPTION_NONE &&
      !ini.section_exist("Profile")) {
    // std::cerr<<"Load profile failed! Reason: "<<ini.get_last_error()<<"\n";
    writeLog(0, "加载配置档失败！原因：" + ini.get_last_error(),
             LOG_LEVEL_ERROR);
    *status_code = 500;
    return "Invalid profile: failed to parse profile content.\n"
           "无效配置：profile 内容解析失败。";
  }
  // std::cerr<<"Trying to parse profile '" + name + "'.\n";
  writeLog(0, "正在解析配置档：'" + name + "'。", LOG_LEVEL_INFO);
  string_multimap contents;
  ini.get_items("Profile", contents);
  if (contents.empty()) {
    // std::cerr<<"Load profile failed! Reason: Empty Profile section\n";
    writeLog(0, "加载配置档失败！原因：[Profile] 配置段为空。",
             LOG_LEVEL_ERROR);
    *status_code = 500;
    return "Invalid profile: [Profile] section is empty.\n"
           "无效配置：[Profile] 配置段为空。\n"
           "Please add at least one profile entry before requesting it.\n"
           "请至少添加一个 profile 条目后再请求。";
  }
  // Token authentication has been disabled - these checks are removed
  // All authentication logic is now bypassed
  // if (profiles.size() == 1 && profile_token != contents.end()) {
  //   authentication skipped
  // }
  /// check if more than one profile is provided
  if (profiles.size() > 1) {
    writeLog(0, "检测到多个配置档，正在合并...",
             LOG_TYPE_INFO);
    std::string all_urls, url;
    auto iter = contents.find("url");
    if (iter != contents.end())
      all_urls = iter->second;
    for (size_t i = 1; i < profiles.size(); i++) {
      name = profiles[i];
      if (!fileExist(name)) {
        writeLog(0, "忽略不存在的配置档：'" + name + "'。",
                 LOG_LEVEL_WARNING);
        continue;
      }
      if (ini.parse_file(name) != INIREADER_EXCEPTION_NONE &&
          !ini.section_exist("Profile")) {
        writeLog(0, "忽略损坏的配置档：'" + name + "'。",
                 LOG_LEVEL_WARNING);
        continue;
      }
      url = ini.get("Profile", "url");
      if (!url.empty()) {
        all_urls += "|" + url;
        writeLog(0, "已添加来自配置档 '" + name + "' 的 URL。", LOG_LEVEL_INFO);
      } else {
        writeLog(0, "配置档 '" + name + "' 没有 url 字段，跳过。",
                 LOG_LEVEL_INFO);
      }
    }
    iter->second = all_urls;
  }

  contents.emplace("token", token);
  contents.emplace("profile_data",
                   base64Encode(global.managedConfigPrefix + "/getprofile?" +
                                joinArguments(argument)));
  std::copy(argument.cbegin(), argument.cend(),
            std::inserter(contents, contents.end()));
  request.argument = contents;
  return subconverter(request, response);
}

/*
std::string jinja2_webGet(const std::string &url)
{
    ProxyPolicy proxy = parseProxy(global.proxyConfig);
    writeLog(0, "模板调用 fetch，URL：'" + url + "'。",
LOG_LEVEL_INFO); return webGet(url, proxy, global.cacheConfig);
}*/

inline std::string intToStream(unsigned long long stream) {
  char chrs[16] = {}, units[6] = {' ', 'K', 'M', 'G', 'T', 'P'};
  double streamval = stream;
  unsigned int level = 0;
  while (streamval > 1024.0) {
    if (level >= 5)
      break;
    level++;
    streamval /= 1024.0;
  }
  snprintf(chrs, 15, "%.2f %cB", streamval, units[level]);
  return {chrs};
}

std::string subInfoToMessage(std::string subinfo) {
  using ull = unsigned long long;
  subinfo = replaceAllDistinct(subinfo, "; ", "&");
  std::string retdata, useddata = "N/A", totaldata = "N/A", expirydata = "N/A";
  std::string upload = getUrlArg(subinfo, "upload"),
              download = getUrlArg(subinfo, "download"),
              total = getUrlArg(subinfo, "total"),
              expire = getUrlArg(subinfo, "expire");
  ull used = to_number<ull>(upload, 0) + to_number<ull>(download, 0),
      tot = to_number<ull>(total, 0);
  auto expiry = to_number<time_t>(expire, 0);
  if (used != 0)
    useddata = intToStream(used);
  if (tot != 0)
    totaldata = intToStream(tot);
  if (expiry != 0) {
    char buffer[30];
    struct tm dt;
    localtime_r(&expiry, &dt);
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M", &dt);
    expirydata.assign(buffer);
  }
  if (useddata == "N/A" && totaldata == "N/A" && expirydata == "N/A")
    retdata = "不可用";
  else
    retdata += "已用流量：" + useddata + " 总流量：" + totaldata +
               " 到期时间：" + expirydata;
  return retdata;
}

int simpleGenerator() {
  // std::cerr<<"\nReading generator configuration...\n";
  writeLog(0, "正在读取生成器配置...", LOG_LEVEL_INFO);
  std::string config = fileGet("generate.ini"), path, profile, content;
  if (config.empty()) {
    // std::cerr<<"Generator configuration not found or empty!\n";
    writeLog(0, "未找到生成器配置，或配置为空！", LOG_LEVEL_ERROR);
    return -1;
  }

  INIReader ini;
  if (ini.parse(config) != INIREADER_EXCEPTION_NONE) {
    // std::cerr<<"Generator configuration broken!
    // Reason:"<<ini.get_last_error()<<"\n";
    writeLog(0,
             "生成器配置损坏！原因：" + ini.get_last_error(),
             LOG_LEVEL_ERROR);
    return -2;
  }
  // std::cerr<<"Read generator configuration completed.\n\n";
  writeLog(0, "生成器配置读取完成。\n", LOG_LEVEL_INFO);

  string_array sections = ini.get_section_names();
  if (!global.generateProfiles.empty()) {
    // std::cerr<<"Generating with specific artifacts:
    // \""<<gen_profile<<"\"...\n";
    writeLog(0,
             "正在按指定生成项生成：\"" + global.generateProfiles + "\"...",
             LOG_LEVEL_INFO);
    string_array targets = split(global.generateProfiles, ","), new_targets;
    for (std::string &x : targets) {
      x = trim(x);
      if (std::find(sections.cbegin(), sections.cend(), x) != sections.cend())
        new_targets.emplace_back(std::move(x));
      else {
        // std::cerr<<"Artifact \""<<x<<"\" not found in generator settings!\n";
        writeLog(0, "生成器设置中未找到生成项：\"" + x + "\"！",
                 LOG_LEVEL_ERROR);
        return -3;
      }
    }
    sections = new_targets;
    sections.shrink_to_fit();
  } else
    // std::cerr<<"Generating all artifacts...\n";
    writeLog(0, "正在生成所有生成项...", LOG_LEVEL_INFO);

  string_multimap allItems;
  ProxyPolicy proxy = parseProxy(global.proxySubscription);
  Request request;
  Response response;
  bool write_failed = false;
  for (std::string &x : sections) {
    response.status_code = 200;
    // std::cerr<<"Generating artifact '"<<x<<"'...\n";
    writeLog(0, "正在生成生成项：'" + x + "'。", LOG_LEVEL_INFO);
    ini.enter_section(x);
    if (ini.item_exist("path"))
      path = ini.get("path");
    else {
      // std::cerr<<"Artifact '"<<x<<"' output path missing! Skipping...\n\n";
      writeLog(0, "生成项 '" + x + "' 缺少输出路径，跳过。\n",
               LOG_LEVEL_ERROR);
      continue;
    }
    if (ini.item_exist("profile")) {
      profile = ini.get("profile");
      request.argument.emplace("name", urlEncode(profile));
      // Token no longer needed as authentication is disabled
      request.argument.emplace("expand", "true");
      content = getProfile(request, response);
    } else {
      if (ini.get_bool("direct")) {
        std::string url = ini.get("url");
        content = fetchFile(url, proxy, global.cacheSubscription);
        if (content.empty()) {
          // std::cerr<<"Artifact '"<<x<<"' generate ERROR! Please check your
          // link.\n\n";
          writeLog(0,
                   "生成项 '" + x + "' 生成失败！请检查链接。\n",
                   LOG_LEVEL_ERROR);
          if (sections.size() == 1)
            return -1;
        }
        // add UTF-8 BOM
        const int write_result =
            fileWrite(path, "\xEF\xBB\xBF" + content, true);
        if (fileCommitFailed(write_result)) {
          writeLog(LOG_LEVEL_ERROR,
                   "生成项 '" + x + "' 写入失败：'" + path + "'。" +
                       (fileCommitTemporaryRemaining(write_result)
                            ? " temporary_file_remaining=true"
                            : " temporary_file_remaining=false"));
          write_failed = true;
          if (sections.size() == 1)
            return -1;
        } else if (fileCommitDurabilityUnconfirmed(write_result)) {
          writeLog(LOG_LEVEL_WARNING,
                   "ARTIFACT_WRITE_VISIBLE target=" + x +
                       " new_file_visible=true durability=unconfirmed "
                       "action=continue");
        }
        continue;
      }
      ini.get_items(allItems);
      allItems.emplace("expand", "true");
      for (auto &y : allItems) {
        if (y.first == "path")
          continue;
        request.argument.emplace(y.first, y.second);
      }
      content = subconverter(request, response);
    }
    if (response.status_code != 200) {
      // std::cerr<<"Artifact '"<<x<<"' generate ERROR! Reason:
      // "<<content<<"\n\n";
      writeLog(0,
               "生成项 '" + x + "' 生成失败！原因：" + content + "\n",
               LOG_LEVEL_ERROR);
      if (sections.size() == 1)
        return -1;
      continue;
    }
    const int write_result = fileWrite(path, content, true);
    if (fileCommitFailed(write_result)) {
      writeLog(LOG_LEVEL_ERROR,
               "生成项 '" + x + "' 写入失败：'" + path + "'。" +
                   (fileCommitTemporaryRemaining(write_result)
                        ? " temporary_file_remaining=true"
                        : " temporary_file_remaining=false"));
      write_failed = true;
      if (sections.size() == 1)
        return -1;
      continue;
    }
    if (fileCommitDurabilityUnconfirmed(write_result)) {
      writeLog(LOG_LEVEL_WARNING,
               "ARTIFACT_WRITE_VISIBLE target=" + x +
                   " new_file_visible=true durability=unconfirmed "
                   "action=continue");
    }
    auto iter =
        std::find_if(response.headers.begin(), response.headers.end(),
                     [](auto y) { return y.first == "Subscription-UserInfo"; });
    if (iter != response.headers.end())
      writeLog(0,
               "生成项 '" + x + "' 的用户信息：" + subInfoToMessage(iter->second),
               LOG_LEVEL_INFO);
    // std::cerr<<"Artifact '"<<x<<"' generate SUCCESS!\n\n";
    writeLog(0, "生成项 '" + x + "' 生成成功！\n", LOG_LEVEL_INFO);
    eraseElements(response.headers);
  }
  // std::cerr<<"All artifact generated. Exiting...\n";
  writeLog(0, "所有生成项已生成，正在退出...", LOG_LEVEL_INFO);
  return 0;
}

std::string renderTemplate(RESPONSE_CALLBACK_ARGS) {
  auto &argument = request.argument;
  int *status_code = &response.status_code;

  std::string path = getUrlArg(argument, "path");
  writeLog(0, "正在渲染模板：'" + path + "'。", LOG_LEVEL_INFO);

  if (!startsWith(path, global.templatePath) || !fileExist(path)) {
    *status_code = 404;
    return "Template not found or outside the allowed template directory.\n"
           "未找到模板，或模板路径超出允许的模板目录。\n"
           "Please provide a path under the configured template directory.\n"
           "请提供位于已配置模板目录下的路径。";
  }
  std::string template_content =
      fetchFile(path, parseProxy(global.proxyConfig, global.proxyBypass),
                global.cacheConfig);
  if (template_content.empty()) {
    *status_code = 400;
    return "Invalid template: file is empty or cannot be read within the "
           "allowed scope.\n"
           "无效模板：文件为空，或无法在允许范围内读取。\n"
           "Please check the template content and configured template path.\n"
           "请检查模板内容和已配置的模板路径。";
  }
  template_args tpl_args;
  tpl_args.global_vars = global.templateVars;

  // load request arguments as template variables
  string_map req_arg_map;
  for (auto &x : argument) {
    req_arg_map[x.first] = x.second;
  }
  tpl_args.request_params = req_arg_map;

  std::string output_content;
  if (render_template(template_content, tpl_args, output_content,
                      global.templatePath) != 0) {
    *status_code = 400;
    writeLog(0, "渲染失败。", LOG_LEVEL_WARNING);
  } else
    writeLog(0, "渲染完成。", LOG_LEVEL_INFO);

  return output_content;
}
