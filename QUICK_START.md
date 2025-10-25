# NOC Toolkit - Quick Start Guide

## 🚀 What's New

Your NOC Toolkit has been completely redesigned with a modern, professional interface!

---

## 📍 Key Changes at a Glance

### Before:
- Simple header with 3 buttons (Changes, Nodes, ToolBox)
- Card-based tool grid on homepage
- Jobs scattered across different pages
- Manual navigation required

### After:
- **Persistent sidebar navigation** - Always visible, organized by category
- **Enhanced dashboard** - Real-time stats, service status, quick access tools
- **Unified Jobs Center** - All background jobs in one searchable, filterable view
- **Toast notifications** - Non-intrusive alerts for all operations
- **Status badges** - Color-coded visual feedback throughout
- **Breadcrumbs** - Never lose your place in the interface
- **Mobile responsive** - Works great on phones and tablets

---

## 🎯 Quick Navigation Guide

### Sidebar Structure:
```
Main
  ├── Dashboard        (Home/Overview)
  └── Jobs Center      (All background jobs)

Config Tools
  ├── Interface Search (Find/modify interface configs)
  ├── Global Config    (Push global changes)
  └── Audit Logs      (View change history)

WLC Tools
  ├── Dashboard       (Wireless monitoring charts)
  ├── AP Inventory    (Access point details)
  ├── RF Summary      (RF utilization stats)
  └── Summer Guest    (Seasonal WLAN monitor)

Infrastructure
  ├── SolarWinds Nodes (Network device inventory)
  ├── Topology         (CDP/LLDP explorer)
  └── Change Windows   (Scheduled changes)
```

---

## 🏠 Dashboard Overview

### Quick Stats (Top Cards):
1. **WLC Clients** - Total connected wireless clients
2. **Access Points** - Total active APs
3. **Background Jobs** - Running operations count
4. **Network Nodes** - Devices in SolarWinds

### Service Status:
- **WLC Dashboard** - Polling status and interval
- **Summer Guest Monitor** - Schedule and last run
- **Change Windows** - Upcoming changes

### Quick Access Tools:
- Large clickable cards for frequently used tools
- Visual icons for easy identification

---

## 💼 Jobs Center - Your New Command Center

Access via sidebar: **Main → Jobs Center**

### What You Can Do:
✅ View all background jobs across all tools
✅ Filter by status (running, completed, failed)
✅ Filter by job type (WLC, topology, config changes)
✅ Search for specific jobs
✅ Sort by any column
✅ Cancel running jobs
✅ View detailed job logs

### Quick Filters:
- **Status:** All / Running / Completed / Failed
- **Job Type:** WLC RF Poll, Interface Actions, etc.
- **Time Range:** Last hour, 24h, 7 days, 30 days

### Job Details:
Click "View" on any job to see:
- Full event timeline
- Job parameters
- Success/failure status
- Real-time updates for running jobs

---

## 📱 Mobile Usage

### Accessing on Mobile:
1. Tap **☰ menu icon** in top-left to open sidebar
2. Navigate using sidebar links
3. Tap outside sidebar or tap X to close

### Mobile Tips:
- All tables are horizontally scrollable
- Touch-friendly button sizes
- Simplified layouts for small screens
- All features available on mobile

---

## 🎨 Status Badge System

Learn to read status at a glance:

- 🟢 **Green (Success)** - Active, completed, running properly
- 🟡 **Yellow (Warning)** - Pending, needs attention
- 🔴 **Red (Error)** - Failed, error state
- 🔵 **Blue (Info)** - Informational, in progress
- ⚪ **Gray (Neutral)** - Inactive, disabled, default

---

## 🔔 Notifications

### Toast Notifications:
Appear in **top-right corner** for:
- Job start/completion
- Configuration changes
- Errors and warnings
- System updates

### Dismissing:
- Click the **X** to close manually
- Auto-dismiss after 5 seconds (default)
- Errors stay longer (8 seconds)

---

## 🔍 Common Tasks - Updated Workflows

### Task: Push Interface Configuration
1. **Sidebar → Config Tools → Interface Search**
2. Enter hosts, credentials, search phrase
3. Click "Search"
4. Select interfaces, choose action
5. Click "Preview & Apply"
6. **New:** Watch job in Jobs Center!

### Task: Monitor Wireless Clients
1. **Sidebar → WLC Tools → Dashboard**
2. View real-time client/AP counts
3. See 24h-30d trend charts
4. Check polling status

### Task: View Recent Changes
1. **Sidebar → Config Tools → Audit Logs**
2. Search/filter changes
3. Export if needed

### Task: Check Background Jobs
1. **Sidebar → Main → Jobs Center**
2. Filter by status or type
3. Click "View" for details
4. Cancel if needed

---

## ⚡ Power User Tips

### Keyboard Navigation:
- Use **Tab** to navigate between elements
- **Enter** to activate buttons/links
- **Esc** to close modals/overlays (mobile sidebar)

### Dashboard Tips:
- Dashboard auto-refreshes stats every 60s
- Click any tool card to jump directly there
- Service status shows last poll times

### Jobs Center Tips:
- Auto-refreshes every 30 seconds
- Use search box for quick filtering
- Click column headers to sort
- "Show X entries" dropdown adjusts page size

### Search Tips:
- Global search in Jobs Center searches all columns
- Combine with filters for precise results
- Results update instantly as you type

---

## 🛠️ Troubleshooting

### Sidebar won't open on mobile:
- Refresh the page
- Check JavaScript console for errors
- Ensure you're tapping the ☰ icon

### Jobs not updating:
- Click "Refresh" button manually
- Check browser network tab for API errors
- Jobs auto-refresh every 30 seconds

### Stats showing "—":
- Services might be paused - check settings
- Data might not be available yet
- Check service status section on dashboard

### Toast notifications not appearing:
- Check browser console for JavaScript errors
- Ensure ad blockers aren't interfering
- Try hard refresh (Ctrl+F5 / Cmd+Shift+R)

---

## 🎓 For NOC Team Members

### Daily Workflow:
1. **Start on Dashboard** - Get overview of system health
2. **Check Jobs Center** - Review overnight jobs
3. **Use Quick Access** - Jump to tools you need
4. **Monitor Status** - Keep eye on service badges

### When Performing Changes:
1. Use appropriate config tool
2. Preview before applying
3. Monitor via Jobs Center
4. Check Audit Logs for confirmation

### Mobile On-Call:
1. Dashboard provides quick overview
2. Jobs Center shows running operations
3. All tools accessible via sidebar
4. Toast notifications keep you informed

---

## 📞 Getting Help

### Understanding the Interface:
- Hover over elements for tooltips (desktop)
- Status badges are color-coded for quick recognition
- Breadcrumbs show where you are

### Technical Questions:
- Refer to `UI_UPGRADES.md` for technical details
- JavaScript API documented for custom integrations
- All components use standard web technologies

---

## ✅ First Time Checklist

On your first login after the upgrade:

- [ ] Explore the new sidebar navigation
- [ ] Check out the enhanced dashboard
- [ ] Visit the Jobs Center
- [ ] Try filtering jobs by status/type
- [ ] View a job detail page
- [ ] Test the mobile sidebar (resize browser)
- [ ] Notice the new status badges
- [ ] Watch for toast notifications
- [ ] Try breadcrumb navigation

---

## 🎉 That's It!

You're ready to use the upgraded NOC Toolkit. The interface is designed to be intuitive - explore and discover features as you work.

**Remember:** All your existing tools work exactly the same way - they just have a better interface now!

**Credential Entry:** As before, you'll enter your credentials when performing searches or making changes. No credential storage has been added.

**Questions?** Review the `UI_UPGRADES.md` file for comprehensive technical documentation.

---

**Happy monitoring! 🚀**
