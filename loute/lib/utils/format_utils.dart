class FormatUtils {
  /// Strips all HTML tags from a given string to provide pure data.
  static String stripHtmlTags(String htmlString) {
    if (htmlString.isEmpty) return '';
    // Regex to match HTML tags
    RegExp exp = RegExp(
      r"<[^>]*>",
      multiLine: true,
      caseSensitive: true,
    );
    // Replace tags with empty string, then decode any standard HTML entities like &nbsp; if needed
    String stripped = htmlString.replaceAll(exp, '');
    stripped = stripped
        .replaceAll('&amp;', '&')
        .replaceAll('&lt;', '<')
        .replaceAll('&gt;', '>')
        .replaceAll('&quot;', '"')
        .replaceAll('&#39;', "'")
        .replaceAll('&nbsp;', ' ');
    return stripped.trim();
  }
}
