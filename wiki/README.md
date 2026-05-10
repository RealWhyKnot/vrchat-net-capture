# Wiki source

The pages in this directory are the source of truth for the GitHub Wiki at https://github.com/RealWhyKnot/vrchat-net-capture/wiki. The wiki-sync workflow mirrors this folder to the GitHub Wiki repo when wiki/** changes on main.

Do not edit pages on github.com after bootstrap. Web edits will be overwritten on the next sync.

Home.md is the wiki landing page. _Sidebar.md controls the sidebar navigation.

## One-time bootstrap

The GitHub Wiki repo ($(System.Collections.Hashtable.Name).wiki.git) only exists after a maintainer creates the first page through the web UI. If wiki-sync reports that the wiki repo does not exist, visit https://github.com/RealWhyKnot/vrchat-net-capture/wiki, create any placeholder page, then re-run wiki-sync. The placeholder will be overwritten by this directory on the next sync.