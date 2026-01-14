# WP Performance & Security Inspector

A lightweight WordPress plugin that audits real-world performance issues and security misconfigurations. Perfect for client audits, website optimization, and maintaining healthy WordPress installations.

![WordPress Version](https://img.shields.io/badge/WordPress-6.0%2B-blue.svg)
![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-purple.svg)
![License](https://img.shields.io/badge/License-GPL%20v2-green.svg)
![Version](https://img.shields.io/badge/Version-1.0.0-orange.svg)

## 📋 Description

**WP Performance & Security Inspector** provides a comprehensive audit of your WordPress website's performance and security configuration. The plugin runs entirely on your server with no external dependencies or paid API requirements.

The plugin analyzes critical aspects of your WordPress installation and provides:
- Clear status indicators (Pass/Warning/Fail)
- Detailed explanations of why each issue matters
- Practical, actionable fix recommendations
- Preference for industry-leading solutions (WP Rocket & Cloudflare)

## ✨ Features

### Performance Audits
- **Active Plugins Count** - Monitors plugin count with warnings at 15+ and alerts at 25+
- **Page Cache Detection** - Checks for WP_CACHE and common caching plugins
- **Object Cache Status** - Detects Redis, Memcached, or APCu implementations
- **CDN Presence** - Identifies Cloudflare, Sucuri, StackPath, and other CDN providers
- **GZIP Compression** - Verifies server-side compression is enabled
- **PHP Version** - Checks for current, supported PHP versions
- **Memory Limit** - Ensures adequate PHP memory allocation
- **Debug Mode** - Warns if debug mode is exposing errors publicly

### Security Audits
- **REST API User Enumeration** - Checks if /wp-json/wp/v2/users exposes usernames
- **XML-RPC Status** - Detects if XML-RPC is enabled and responding
- **User Registration** - Monitors public registration settings and default roles
- **WordPress Version Exposure** - Checks for version leaks in meta tags and files
- **SSL/HTTPS Configuration** - Verifies proper HTTPS implementation
- **File Editing** - Checks if theme/plugin editor is disabled
- **Database Prefix** - Identifies use of default wp_ prefix
- **Admin Username** - Detects common admin usernames (admin, administrator)

## 🎯 Use Cases

1. **Client Website Audits** - Quickly assess a client's WordPress site health
2. **Pre-Launch Checklists** - Verify security and performance before going live
3. **Maintenance Reviews** - Regular health checks for managed sites
4. **Security Hardening** - Identify and address security misconfigurations
5. **Performance Optimization** - Find quick wins for speed improvements
6. **Developer Onboarding** - Understand a new project's current state
7. **Documentation** - Generate audit reports for clients or stakeholders

## 📦 Installation

### Manual Installation

1. Download the plugin ZIP file or clone the repository
2. Upload to `/wp-content/plugins/wp-performance-security-inspector/`
3. Activate the plugin through the 'Plugins' menu in WordPress
4. Navigate to 'Site Inspector' in the admin menu

### From GitHub

```bash
cd /path/to/wordpress/wp-content/plugins/
git clone https://github.com/razuahammad/wp-performance-security-inspector.git
