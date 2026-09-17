//! The sitemap against the directory it describes.
//!
//! Not a style check. Search Console for this property read the sitemap
//! successfully, found six URLs, and indexed six pages — which was correct
//! and also the whole problem: the site had six pages worth listing and
//! nothing told anybody that the number should have been larger. The
//! failure mode of a hand-written sitemap is silence. A page is added, the
//! file is not touched, nothing breaks, nothing logs, and the page simply
//! never ranks.
//!
//! So this reads `web/` and `web/sitemap.xml` and insists they agree in
//! both directions: every indexable page is listed, and every listed URL
//! exists and is indexable. It needs no database and no network.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

fn web_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/api.
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../web")
        .canonicalize()
        .expect("the web directory should be two levels up from crates/api")
}

/// Pages that exist on disk but are deliberately not their own address.
///
/// `landing.html` and `index.html` are the files behind `/` and `/app`,
/// and both redirect to those (see `with_static_files`). Anything
/// noindexed is filtered separately, by reading the file.
const NOT_OWN_PAGE: [&str; 2] = ["landing.html", "index.html"];

fn indexable_pages(root: &Path) -> BTreeSet<String> {
    let mut pages = BTreeSet::new();
    for entry in std::fs::read_dir(root).expect("web directory should be readable") {
        let path = entry.expect("readable entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("html") {
            continue;
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .expect("a file name")
            .to_string();
        if NOT_OWN_PAGE.contains(&name.as_str()) {
            continue;
        }
        let body = std::fs::read_to_string(&path).expect("readable page");
        // Crude on purpose: matching the literal string a page would have
        // to contain to be noindexed is more robust here than parsing
        // HTML, and errs toward demanding a sitemap entry.
        if body.contains("name=\"robots\"") && body.contains("noindex") {
            continue;
        }
        pages.insert(name);
    }
    pages
}

fn sitemap_entries(root: &Path) -> Vec<(String, Option<String>)> {
    let xml = std::fs::read_to_string(root.join("sitemap.xml")).expect("a sitemap");
    xml.split("<url>")
        .skip(1)
        .map(|block| {
            let between = |open: &str, close: &str| -> Option<String> {
                let start = block.find(open)? + open.len();
                let end = block[start..].find(close)? + start;
                Some(block[start..end].trim().to_string())
            };
            (
                between("<loc>", "</loc>").expect("every <url> needs a <loc>"),
                between("<lastmod>", "</lastmod>"),
            )
        })
        .collect()
}

#[test]
fn every_indexable_page_is_listed_in_the_sitemap() {
    let root = web_root();
    let listed: BTreeSet<String> = sitemap_entries(&root)
        .into_iter()
        .map(|(loc, _)| {
            loc.trim_start_matches("https://glarion.app/")
                .trim_end_matches('/')
                .to_string()
        })
        .collect();

    let missing: Vec<String> = indexable_pages(&root)
        .into_iter()
        .filter(|page| !listed.contains(page))
        .collect();

    assert!(
        missing.is_empty(),
        "these pages are indexable and absent from web/sitemap.xml, so nothing \
         will ever tell a crawler they exist: {missing:?}"
    );
}

#[test]
fn every_sitemap_url_points_at_a_page_that_wants_to_be_indexed() {
    let root = web_root();

    for (loc, _) in sitemap_entries(&root) {
        assert!(
            loc.starts_with("https://glarion.app/"),
            "every entry must use the canonical origin: {loc}"
        );

        let path = loc.trim_start_matches("https://glarion.app/");
        // The root is landing.html, which is listed as "/" and nothing else.
        let file = if path.is_empty() {
            "landing.html".to_string()
        } else {
            path.to_string()
        };

        let full = root.join(&file);
        assert!(full.exists(), "{loc} is listed but {file} does not exist");

        let body = std::fs::read_to_string(&full).expect("readable page");
        assert!(
            !(body.contains("name=\"robots\"") && body.contains("noindex")),
            "{loc} is in the sitemap and noindexed, which asks a crawler to \
             fetch a page and then ignore what it found"
        );

        if !path.is_empty() {
            assert!(
                !NOT_OWN_PAGE.contains(&file.as_str()),
                "{loc} redirects elsewhere and must not be listed"
            );
        }
    }
}

#[test]
fn every_sitemap_url_carries_a_lastmod() {
    // Without one a crawler has no reason to prefer a recrawl of a page
    // that changed over one that did not, which is most of what a sitemap
    // is for once the URLs are already known.
    for (loc, lastmod) in sitemap_entries(&web_root()) {
        let lastmod = lastmod.unwrap_or_else(|| panic!("{loc} has no <lastmod>"));
        assert_eq!(
            lastmod.len(),
            10,
            "{loc} has a <lastmod> that is not a YYYY-MM-DD date: {lastmod}"
        );
        assert!(
            lastmod.chars().filter(|c| *c == '-').count() == 2,
            "{loc} has a <lastmod> that is not a YYYY-MM-DD date: {lastmod}"
        );
    }
}

#[test]
fn every_indexable_page_has_a_self_referencing_canonical() {
    // The one tag that decides which address a page's ranking accrues to.
    // A copy-pasted page that keeps the canonical of the page it was
    // copied from hands its results to that page instead, and looks
    // completely fine until somebody checks.
    let root = web_root();
    for page in indexable_pages(&root) {
        let body = std::fs::read_to_string(root.join(&page)).expect("readable page");
        let expected = if page == "landing.html" {
            "https://glarion.app/".to_string()
        } else {
            format!("https://glarion.app/{page}")
        };
        assert!(
            body.contains(&format!("rel=\"canonical\" href=\"{expected}\"")),
            "{page} should carry a canonical pointing at {expected}"
        );
    }
}

#[test]
fn every_indexable_page_has_a_title_and_a_description_search_can_use() {
    let root = web_root();
    for page in indexable_pages(&root) {
        let body = std::fs::read_to_string(root.join(&page)).expect("readable page");

        let title = body
            .split_once("<title>")
            .and_then(|(_, rest)| rest.split_once("</title>"))
            .map(|(title, _)| title.trim().to_string())
            .unwrap_or_else(|| panic!("{page} has no <title>"));
        // Counted in characters rather than bytes: the titles contain em
        // dashes and euro signs, and a byte count would fail on those for
        // no reason a reader of a search result would recognise.
        let length = title.chars().count();
        assert!(
            (10..=60).contains(&length),
            "{page} has a {length}-character title; Google truncates past \
             about 60: {title}"
        );

        let marker = "name=\"description\" content=\"";
        let description = body
            .split_once(marker)
            .and_then(|(_, rest)| rest.split_once('"'))
            .map(|(value, _)| value.trim().to_string())
            .unwrap_or_else(|| panic!("{page} has no meta description"));
        let length = description.chars().count();
        assert!(
            (140..=160).contains(&length),
            "{page} has a {length}-character description; under about 140 \
             invites Google to write its own from the page body, and past \
             160 the end is cut off: {description}"
        );
    }
}
