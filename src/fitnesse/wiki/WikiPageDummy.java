// Copyright (C) 2003-2009 by Object Mentor, Inc. All rights reserved.
// Released under the terms of the CPL Common Public License version 1.0.

package fitnesse.wiki;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import util.Clock;

public class WikiPageDummy implements WikiPage {
  private static final long serialVersionUID = 1L;

  public String name;
  private PageData pageData;
  private WikiPage parent;

  public WikiPageDummy(String name, String content) {
    this.name = name;
    pageData = new PageData(this);
    pageData.setContent(content);
  }

  public WikiPageDummy() {
    name = "Default";
    pageData = new PageData(this);
  }

  public WikiPageDummy(ReadOnlyPageData pageData) {
    name = "Default";
    this.pageData = (PageData) pageData;
    this.pageData.setWikiPage(this);
  }

  public String getName() {
    return name;
  }

  public WikiPage getParent() {
    return parent;
  }

  public void setParent(WikiPage parent) {
    this.parent = parent;
  }

  public boolean isRoot() {
    return parent == null;
  }

  public PageData getData() {
    return pageData;
  }

  public ReadOnlyPageData readOnlyData() { return getData(); }

  @Override
  public Collection<VersionInfo> getVersions() {
    return Collections.emptySet();
  }

  public VersionInfo commit(PageData data) {
    pageData = data;
    return new VersionInfo("mockVersionName", "mockAuthor", Clock.currentDate());
  }

  public List<WikiPage> getChildren() {
    return new ArrayList<WikiPage>();
  }

  public int compareTo(Object o) {
    return 0;
  }

  @Override
  public WikiPage getVersion(String versionName) {
    return this;
  }

  @Override
  public String getHtml() {
    return getData().getHtml();
  }

  public void removeChildPage(String name) {
  }

  public PageCrawler getPageCrawler() {
    return new PageCrawlerImpl(this);
  }

  public WikiPage getHeaderPage() {
    return null;
  }

  public WikiPage getFooterPage() {
    return null;
  }

  @Override
  public String getVariable(String name) {
    return null;
  }

  @Override
  public List<String> getXrefPages() {
    return Collections.emptyList();
  }

  public WikiPage addChildPage(String name) {
    return null;
  }

  public boolean hasChildPage(String name) {
    return false;
  }

  public WikiPage getChildPage(String name) {
    return null;
  }

}
