// Copyright (C) 2003-2009 by Object Mentor, Inc. All rights reserved.
// Released under the terms of the CPL Common Public License version 1.0.
package fitnesse.testsystems.slim;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Random;

import fitnesse.slim.SlimError;
import org.htmlparser.Node;
import org.htmlparser.Parser;
import org.htmlparser.lexer.Lexer;
import org.htmlparser.lexer.Page;
import org.htmlparser.tags.TableTag;
import org.htmlparser.util.NodeList;
import org.htmlparser.util.ParserException;

// TODO: TableScanner should return a list of Tables and page content fragments
// TODO: Need logic to split (by clone) data blocks and and to render (to html) those blocks
public class HtmlTableScanner implements TableScanner<HtmlTable> {

  // This should contain content blobs (List<Object>?)
  private List<HtmlTable> tables = new ArrayList<HtmlTable>();
  private NodeList htmlTree;

  public HtmlTableScanner(String page) {
    if (page == null || page.equals(""))
      page = "<i>This page intentionally left blank.</i>";

    try {
      Parser parser = new Parser(new Lexer(new Page(page)));
      htmlTree = parser.parse(null);
    } catch (ParserException e) {
      throw new SlimError(e);
    }
    scanForTables(htmlTree);
  }

  public HtmlTableScanner(String... fragments) {
    try {
      htmlTree = new NodeList();
      for (String fragment: fragments) {
        Parser parser = new Parser(new Lexer(new Page(fragment)));
        NodeList tree = parser.parse(null);
        htmlTree.add(tree);
      }
    } catch (ParserException e) {
      throw new SlimError(e);
    }
    scanForTables(htmlTree);
  }

  private void scanForTables(NodeList nodes) {
    for (int i = 0; i < nodes.size(); i++) {
      Node node = nodes.elementAt(i);
      if (node instanceof TableTag) {
        TableTag tableTag = (TableTag) node;
        guaranteeThatAllTablesAreUnique(tableTag);
        tables.add(new HtmlTable(tableTag));
      } else {
        NodeList children = node.getChildren();
        if (children != null)
          scanForTables(children);
      }
    }
  }

  private void guaranteeThatAllTablesAreUnique(TableTag tagTable) {
    tagTable.setAttribute("_TABLENUMBER", ""+ Math.abs((new Random()).nextLong()), '"');
  }

  public int getTableCount() {
    return tables.size();
  }

  public HtmlTable getTable(int i) {
    return tables.get(i);
  }

  public Iterator<HtmlTable> iterator() {
    return tables.iterator();
  }

  public String toHtml(HtmlTable startTable, HtmlTable endBeforeTable) {
    String allHtml = htmlTree.toHtml();

    int startIndex = 0;
    int endIndex = allHtml.length();
    if (startTable != null) {
      String startText = startTable.toHtml();
      int nodeIndex = allHtml.indexOf(startText);
      if (nodeIndex > 0) {
        startIndex = nodeIndex;
      }
    }
    
    if (endBeforeTable != null) {
      String stopText = endBeforeTable.toHtml();
      int nodeIndex = allHtml.indexOf(stopText);
      if (nodeIndex > 0) {
        endIndex = nodeIndex;
      }
    }
    return allHtml.substring(startIndex, endIndex);
  }
  
  public String toHtml() {
    return htmlTree.toHtml();
  }
}
