# PRD: UI Consistency & Design Standardization

## Introduction

Comprehensive UI/UX overhaul of the NOC Toolkit to establish visual consistency across all 57 templates. This includes fixing the theme flash issue, standardizing page layouts to follow the `wlc_dashboard.html` design pattern (page header with gradient accent bar, organized card sections), and ensuring all pages have proper structure rather than basic vertical layouts.

## Goals

- Eliminate dark theme flash when light theme is selected
- Standardize all pages to follow the wlc_dashboard.html design pattern
- Add proper page headers with gradient accent bars to all pages
- Convert basic vertical layouts to organized card-based sections
- Move inline `<style>` blocks to base.html component system
- Ensure consistent spacing, typography, and interactive elements
- Full Playwright verification with screenshots and interaction testing

## User Stories

### US-001: Fix Theme Flash on Page Load
**Description:** As a user with light theme selected, I want pages to load without showing dark theme first so that the experience is seamless.

**Acceptance Criteria:**
- [ ] Move theme detection from body script to blocking script in `<head>` before any CSS loads
- [ ] Theme is applied before first paint (no flash)
- [ ] Works on page refresh and navigation
- [ ] localStorage preference is respected immediately
- [ ] Verify in browser using Playwright - capture screenshots in both modes

---

### US-002: Create Reusable Page Header Component in base.html
**Description:** As a developer, I need a standardized page header component so all pages have consistent headers.

**Acceptance Criteria:**
- [ ] Add `.page-header` CSS class to base.html with:
  - White/navy background with border
  - 1px gradient accent bar at top (pink to navy)
  - Rounded corners (2xl)
  - Proper padding (p-7)
  - Flex layout for title + actions
- [ ] Add `.page-header-title` for h2 styling (font-display, 2xl, bold)
- [ ] Add `.page-header-subtitle` for description text
- [ ] Add `.page-header-actions` for button group styling
- [ ] Document usage pattern in comments
- [ ] Verify in browser using Playwright

---

### US-003: Redesign cert_converter.html
**Description:** As a user, I want the Certificate Converter page to have proper structure and match the design system.

**Acceptance Criteria:**
- [ ] Add page header with gradient accent bar (matching wlc_dashboard.html)
- [ ] Replace inline `<style>` with Tailwind classes and base.html components
- [ ] Keep conversion cards grid but use `.card` class styling
- [ ] Add proper icon boxes with gradient backgrounds
- [ ] Use `.field` classes for form inputs
- [ ] Use `.btn-gradient` for primary submit buttons
- [ ] Remove inline style attributes where possible
- [ ] Verify in browser using Playwright - test all 6 conversion forms

---

### US-004: Redesign cert_tracker.html
**Description:** As a user, I want the Certificate Tracker page to match the standard design pattern.

**Acceptance Criteria:**
- [ ] Add page header with gradient accent bar instead of inline styled header
- [ ] Move stat card styles to base.html or use Tailwind classes
- [ ] Use `.card` class for filter bar container
- [ ] Keep existing table and stat card functionality
- [ ] Standardize button styling with `.btn` classes
- [ ] Remove inline `<style>` block where possible
- [ ] Verify in browser using Playwright - test filters and stat card clicks

---

### US-005: Redesign ise_nodes.html
**Description:** As a user, I want the ISE Nodes page to have consistent structure and styling.

**Acceptance Criteria:**
- [ ] Add page header with gradient accent bar
- [ ] Replace back link with proper breadcrumb or include in header
- [ ] Move node card styles to use Tailwind or base.html components
- [ ] Use `.card` class for add node form
- [ ] Standardize action buttons with `.btn` classes
- [ ] Keep search and filter functionality
- [ ] Remove inline `<style>` block
- [ ] Verify in browser using Playwright - test add form toggle, search, and node actions

---

### US-006: Redesign phrase_search.html
**Description:** As a user, I want the Phrase Search page to match the modern card-based design pattern.

**Acceptance Criteria:**
- [ ] Add page header with gradient accent bar
- [ ] Convert `.form-section` pattern to card-based layout
- [ ] Use `.card` class for form container
- [ ] Use `.field` classes for inputs
- [ ] Keep form sections organized but use card spacing instead of custom dividers
- [ ] Remove tool-header custom styling
- [ ] Verify in browser using Playwright - test form submission

---

### US-007: Redesign global_config.html
**Description:** As a user, I want the Global Config page to match the modern design pattern.

**Acceptance Criteria:**
- [ ] Add page header with gradient accent bar
- [ ] Convert `.form-section` pattern to card-based layout
- [ ] Use `.card` class for form sections
- [ ] Consistent spacing with other pages
- [ ] Remove custom form-section styling
- [ ] Verify in browser using Playwright - test form functionality

---

### US-008: Redesign ise_node_edit.html
**Description:** As a user, I want the ISE Node Edit page to have full page structure.

**Acceptance Criteria:**
- [ ] Add page header with "Edit ISE Node" title
- [ ] Add breadcrumb navigation (ISE Nodes > Edit)
- [ ] Wrap form in `.card` container
- [ ] Use `.field` classes for all inputs
- [ ] Add proper button styling with `.btn-gradient` for save
- [ ] Verify in browser using Playwright - test form editing

---

### US-009: Redesign profile.html
**Description:** As a user, I want the Profile page to have proper structure.

**Acceptance Criteria:**
- [ ] Add page header with "My Profile" title
- [ ] Wrap form sections in `.card` containers
- [ ] Organize fields in logical groups (Account Info, Security)
- [ ] Use `.field` classes for inputs
- [ ] Verify in browser using Playwright

---

### US-010: Redesign solarwinds_nodes_settings.html
**Description:** As a user, I want the SolarWinds settings page to have consistent structure.

**Acceptance Criteria:**
- [ ] Add page header with gradient accent bar
- [ ] Wrap settings form in `.card` container
- [ ] Use `.field` classes for inputs
- [ ] Match layout pattern of wlc_dashboard_settings.html
- [ ] Verify in browser using Playwright

---

### US-011: Redesign wlc_tools.html
**Description:** As a user, I want the WLC Tools page to have proper page structure.

**Acceptance Criteria:**
- [ ] Add page header with gradient accent bar
- [ ] Use card grid for tool links (similar to index.html tool cards)
- [ ] Add icons and descriptions to each tool link
- [ ] Verify in browser using Playwright

---

### US-012: Standardize index.html Dashboard
**Description:** As a user, I want the dashboard to follow the same header pattern as other pages.

**Acceptance Criteria:**
- [ ] Add page header component (or update existing layout to match pattern)
- [ ] Ensure stat cards and tool cards use consistent styling
- [ ] Remove any inline styles in favor of Tailwind/base.html classes
- [ ] Verify in browser using Playwright

---

### US-013: Standardize login.html
**Description:** As a user, I want the login page to have polished, consistent design.

**Acceptance Criteria:**
- [ ] Review and update to use consistent `.card` and `.field` styling
- [ ] Ensure proper spacing and typography
- [ ] Verify in browser using Playwright - test login form

---

### US-014: Standardize audit_logs.html
**Description:** As a user, I want the Audit Logs page to maintain its good design but use component classes.

**Acceptance Criteria:**
- [ ] Review existing page header (already good)
- [ ] Ensure custom styles are consolidated into base.html if reusable
- [ ] Verify in browser using Playwright - test search and filters

---

### US-015: Standardize bulk_ssh.html
**Description:** As a user, I want the Bulk SSH page to have consistent structure.

**Acceptance Criteria:**
- [ ] Verify page header follows standard pattern
- [ ] Ensure form sections use card-based layout
- [ ] Review and consolidate any custom styles
- [ ] Verify in browser using Playwright - test form and tabs

---

### US-016: Standardize device_inventory.html
**Description:** As a user, I want the Device Inventory page to match the design system.

**Acceptance Criteria:**
- [ ] Verify page header follows standard pattern
- [ ] Ensure table and filters use consistent styling
- [ ] Verify in browser using Playwright

---

### US-017: Standardize customer_dashboard.html
**Description:** As a user, I want the Customer Dashboard to have consistent structure.

**Acceptance Criteria:**
- [ ] Verify page header follows standard pattern
- [ ] Ensure cards and stats use consistent styling
- [ ] Verify in browser using Playwright

---

### US-018: Standardize knowledge_base.html and related pages
**Description:** As a user, I want Knowledge Base pages to match the design system.

**Acceptance Criteria:**
- [ ] Verify knowledge_base.html has proper page header
- [ ] Verify knowledge_base_form.html uses card-based form layout
- [ ] Verify knowledge_base_article.html has proper structure
- [ ] Verify in browser using Playwright

---

### US-019: Standardize jobs_center.html and job_detail.html
**Description:** As a user, I want Jobs pages to have consistent structure.

**Acceptance Criteria:**
- [ ] Verify jobs_center.html has proper page header
- [ ] Verify job_detail.html has proper page structure
- [ ] Ensure job cards/tables use consistent styling
- [ ] Verify in browser using Playwright

---

### US-020: Standardize topology pages
**Description:** As a user, I want Topology pages to have consistent headers.

**Acceptance Criteria:**
- [ ] Verify topology_builder.html has proper page header
- [ ] topology_graph.html can keep specialized layout but header should match
- [ ] Verify in browser using Playwright

---

### US-021: Standardize WLC troubleshooting pages
**Description:** As a user, I want WLC troubleshooting pages to have consistent structure.

**Acceptance Criteria:**
- [ ] Review wlc_clients_troubleshoot.html, wlc_rf_troubleshoot.html
- [ ] Ensure page headers and forms follow standard pattern
- [ ] Verify in browser using Playwright

---

### US-022: Standardize results pages
**Description:** As a user, I want all results pages to have consistent structure.

**Acceptance Criteria:**
- [ ] Review results.html, wlc_results.html, global_config_results.html, bulk_ssh_results.html
- [ ] Add page headers where missing
- [ ] Ensure result displays use consistent card styling
- [ ] Verify in browser using Playwright

---

### US-023: Standardize admin pages
**Description:** As a user, I want admin pages to have consistent structure.

**Acceptance Criteria:**
- [ ] Verify admin_users.html follows standard pattern
- [ ] Verify admin_page_settings.html has proper header
- [ ] Verify in browser using Playwright

---

### US-024: Consolidate Custom CSS into base.html
**Description:** As a developer, I need reusable styles centralized so templates are cleaner.

**Acceptance Criteria:**
- [ ] Identify common patterns in template `<style>` blocks
- [ ] Add reusable classes to base.html:
  - `.stat-card` with color variants
  - `.node-card` for list items
  - `.conversion-card` for tool options
  - `.filter-bar` for search/filter sections
  - Modal styling as `.modal` component
- [ ] Update templates to use new classes
- [ ] Remove duplicate `<style>` blocks from templates
- [ ] Verify in browser using Playwright

---

### US-025: Create Playwright Test Suite for Visual Verification
**Description:** As a developer, I need comprehensive Playwright tests to verify all pages.

**Acceptance Criteria:**
- [ ] Create test file that visits all 57 pages
- [ ] Take screenshots in both light and dark mode
- [ ] Test key interactions:
  - Theme toggle
  - Form submissions
  - Button clicks
  - Modal opening/closing
  - Tab switching
  - Search/filter functionality
- [ ] Generate visual regression report
- [ ] All pages render without JavaScript errors

---

### US-026: Final Visual Audit
**Description:** As a user, I want all pages to look consistent and professional.

**Acceptance Criteria:**
- [ ] Review all 57 pages in browser
- [ ] Verify consistent spacing (mb-6 between sections)
- [ ] Verify consistent typography (font-display for headings)
- [ ] Verify consistent colors (pink/navy accent palette)
- [ ] Verify all buttons use `.btn` variants
- [ ] Verify all forms use `.field` classes
- [ ] No orphaned custom styles
- [ ] Verify in browser using Playwright - full screenshot suite

---

## Functional Requirements

- FR-1: Theme must be applied before first paint to prevent flash
- FR-2: All pages must have a page header with gradient accent bar (except login which has special layout)
- FR-3: All forms must use `.field` class styling for labels and inputs
- FR-4: All buttons must use `.btn` variants (primary: `.btn-gradient`, secondary: `.btn-secondary`)
- FR-5: All content sections must use `.card` class containers
- FR-6: Custom styles must be in base.html, not inline in templates
- FR-7: All pages must work in both light and dark modes
- FR-8: All pages must be responsive (mobile-friendly)
- FR-9: Page headers must include title, subtitle, and action buttons (where applicable)
- FR-10: Stat cards must use consistent color coding for status indicators

## Non-Goals

- No new features or functionality changes
- No backend/API changes
- No changes to existing data models
- No accessibility audit (separate initiative)
- No performance optimization (separate initiative)
- No changes to navigation structure

## Design Considerations

### Page Header Pattern (from wlc_dashboard.html)
```html
<div class="page-header">
  <div class="flex justify-between items-start gap-5 flex-wrap">
    <div class="flex-1">
      <h2 class="page-header-title">Page Title</h2>
      <p class="page-header-subtitle">Description text here</p>
    </div>
    <div class="page-header-actions">
      <a class="btn btn-secondary" href="#">Action 1</a>
      <a class="btn btn-gradient" href="#">Primary Action</a>
    </div>
  </div>
</div>
```

### Stat Card Pattern
```html
<div class="stat-card">
  <div class="stat-icon"><!-- SVG icon --></div>
  <div class="stat-label">Label</div>
  <div class="stat-value">123</div>
</div>
```

### Form Section Pattern
```html
<div class="card">
  <h3 class="section-title">Section Title</h3>
  <div class="field">
    <label>Field Label</label>
    <input type="text" ...>
  </div>
</div>
```

## Technical Considerations

- Theme flash fix requires moving script to `<head>` with synchronous execution
- CSS classes should be added to base.html's `<style>` block (lines 113-564)
- Tailwind CDN is used - custom classes must be in style block, not config
- Test pages require running Flask app locally
- Playwright tests should use accessibility snapshots for reliable element selection

## Success Metrics

- Zero theme flash on any page when user has light theme selected
- 100% of pages have standardized page headers
- 0 inline `<style>` blocks with duplicate patterns
- All Playwright tests pass (screenshots + interactions)
- Consistent visual appearance across all 57 templates

## Open Questions

- Should we create a shared partials/includes system for common components?
- Should settings pages (wlc_dashboard_settings, etc.) have different header treatment?
- Priority order for page redesigns if done incrementally?

## Template Inventory (57 pages)

### Priority 1 - Needs Redesign (Basic/Inconsistent)
1. cert_converter.html
2. ise_nodes.html
3. ise_node_edit.html
4. phrase_search.html
5. global_config.html
6. profile.html
7. solarwinds_nodes_settings.html
8. wlc_tools.html

### Priority 2 - Needs Header Standardization
9. cert_tracker.html
10. index.html
11. login.html
12. error.html

### Priority 3 - Review & Consolidate Styles
13. wlc_dashboard.html (reference standard)
14. audit_logs.html
15. admin_users.html
16. admin_page_settings.html
17. bulk_ssh.html
18. bulk_ssh_results.html
19. bulk_ssh_jobs.html
20. bulk_ssh_templates.html
21. bulk_ssh_schedules.html
22. device_inventory.html
23. solarwinds_nodes.html
24. customer_dashboard.html
25. topology_builder.html
26. topology_graph.html
27. changes.html
28. change_detail.html
29. knowledge_base.html
30. knowledge_base_form.html
31. knowledge_base_article.html
32. jobs_center.html
33. job_detail.html
34. job_progress.html
35. results.html
36. action_preview.html
37. action_preview_global.html
38. action_result.html
39. wlc_inventory.html
40. wlc_rf.html
41. wlc_summer_guest.html
42. wlc_clients_troubleshoot.html
43. wlc_clients_troubleshoot_job.html
44. wlc_clients_troubleshoot_jobs.html
45. wlc_rf_troubleshoot.html
46. wlc_rf_troubleshoot_job.html
47. wlc_rf_results.html
48. wlc_results.html
49. wlc_dashboard_settings.html
50. wlc_summer_guest_settings.html
51. cert_upload.html
52. cert_edit.html
53. cert_view.html
54. cert_chain.html
55. global_config_results.html

### Base Template
56. base.html (component system lives here)
