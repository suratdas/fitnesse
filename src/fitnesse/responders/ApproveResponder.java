package fitnesse.responders;

import fitnesse.FitNesseContext;
import fitnesse.authentication.SecureOperation;
import fitnesse.authentication.SecureResponder;
import fitnesse.authentication.SecureWriteOperation;
import fitnesse.html.template.HtmlPage;
import fitnesse.html.template.PageTitle;
import fitnesse.http.Request;
import fitnesse.http.Response;
import fitnesse.http.SimpleResponse;
import fitnesse.responders.editing.SaveRecorder;
import fitnesse.wiki.*;

import java.io.UnsupportedEncodingException;
import java.util.List;

public class ApproveResponder implements SecureResponder {

  private SimpleResponse simpleResponse;
  private String qualifiedPageName;
  private WikiPagePath path;
  private FitNesseContext context;

  @Override
  public Response makeResponse(FitNesseContext context, Request request) throws Exception {
    this.context = context;
    this.simpleResponse = new SimpleResponse();
    this.qualifiedPageName = request.getResource();
    this.path = PathParser.parse(qualifiedPageName);

    tryToApprovePage(request);
    return simpleResponse;
  }

  private void tryToApprovePage(Request request) throws UnsupportedEncodingException {
    String confirmedString = request.getInput("confirmed");
    if (!"yes".equalsIgnoreCase(confirmedString)) {
      simpleResponse.setContent(buildConfirmationHtml(context.getRootPage(), qualifiedPageName, context, request));
    } else {
      String user = request.getAuthorizationUsername();
      WikiPage parent = context.getRootPage().getPageCrawler().getPage(path);
      changePageApproverProperty(parent.getData(), parent, user);
      for (WikiPage eachPage : parent.getChildren()) {
        changePageApproverProperty(eachPage.getData(), eachPage, user);
      }
      redirect(path, simpleResponse);
    }
  }

  private void changePageApproverProperty(PageData data, WikiPage page, String user) {
    data.setAttribute(PageData.PropertyApprover, String.valueOf(user));
    data.setAttribute(PageData.PropertyCommitted, "false");
    SaveRecorder.pageSaved(page, SaveRecorder.newTicket());
    page.commit(data);
  }

  private void redirect(final WikiPagePath path, final SimpleResponse response) {
    String location = PathParser.render(path);
    if (location == null || location.isEmpty()) {
      response.redirect(context.contextRoot, "root");
    } else {
      response.redirect(context.contextRoot, location);
    }
  }


  private String buildConfirmationHtml(final WikiPage root, final String qualifiedPageName, final FitNesseContext context, Request request) {
    HtmlPage html = context.pageFactory.newPage();

    String tags = "";

    WikiPagePath path = PathParser.parse(qualifiedPageName);
    PageCrawler crawler = root.getPageCrawler();
    WikiPage wikiPage = crawler.getPage(path);
    if (wikiPage != null) {
      PageData pageData = wikiPage.getData();
      tags = pageData.getAttribute(WikiPageProperty.SUITES);
    }

    html.setTitle("Approve Confirmation");
    html.setPageTitle(new PageTitle("Confirm Approval", PathParser.parse(qualifiedPageName), tags));

    makeMainContent(html, root, qualifiedPageName);
    html.setMainTemplate("approvePage");
    return html.html(request);
  }

  private void makeMainContent(final HtmlPage html, final WikiPage root, final String qualifiedPageName) {
    WikiPagePath path = PathParser.parse(qualifiedPageName);
    WikiPage pageToApprove = root.getPageCrawler().getPage(path);
    List<WikiPage> children = pageToApprove.getChildren();

    html.put("approveSubPages", children != null && !children.isEmpty());
    html.put("pageName", qualifiedPageName);
  }

  @Override
  public SecureOperation getSecureOperation() {
    return new SecureWriteOperation();
  }
}
