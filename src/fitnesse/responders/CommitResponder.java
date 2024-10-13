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
import fitnesse.wiki.fs.WikiFilePage;
import org.eclipse.jgit.api.Git;
import org.eclipse.jgit.api.Status;
import org.eclipse.jgit.lib.Repository;
import org.eclipse.jgit.storage.file.FileRepositoryBuilder;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class CommitResponder implements SecureResponder {

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
    try {
      tryToCommitPage(request);
      return simpleResponse;
    } catch (Exception ex) {
      Response errorResponse = new ErrorResponder("Commit error : " + ex.getMessage()).makeResponse(context, null);
      errorResponse.setStatus(404);
      return errorResponse;
    }
    /*
    String resource = request.getResource();
    WikiPage page = getPage(resource, context);
    String user = request.getAuthorizationUsername();
    Response response = new SimpleResponse();
    PageData data = page.getData();
    try {
      changePageCommittedProperty(data, page, true);
      String pagePath = ((WikiFilePage) page).getFileSystemPath().getCanonicalPath() + ".wiki";
      Repository repository = new FileRepositoryBuilder().findGitDir(new File(pagePath)).build();
      Git git = new Git(repository);
      pagePath = ((WikiFilePage) page).getFileSystemPath().getPath().replace("./", "") + ".wiki";
      git.add().addFilepattern(pagePath).call();
      Status status = git.status().call();
      if (status.getAdded().size() + status.getChanged().size() == 1) {
        git.commit().setMessage(user + " : " + page.getFullPath()).call();
        context.recentChanges.updateRecentChanges(page);
      } else {
        throw new Exception("No file was found to be eligible for commit.");
      }
    } catch (Exception ex) {
      changePageCommittedProperty(data, page, false);
      response = new ErrorResponder("Commit error : " + ex.getMessage()).makeResponse(context, null);
      response.setStatus(404);
      return response;
    }
    response.redirect(context.contextRoot, request.getResource());
    return response;
     */
  }

  private void tryToCommitPage(Request request) throws Exception {
    String confirmedString = request.getInput("confirmed");
    if (!"yes".equalsIgnoreCase(confirmedString)) {
      simpleResponse.setContent(buildConfirmationHtml(context.getRootPage(), qualifiedPageName, context, request));
    } else {
      List<WikiPage> pagesToProcess = new ArrayList<>();
      String user = request.getAuthorizationUsername();
      try {
        WikiPage parent = context.getRootPage().getPageCrawler().getPage(path);
        pagesToProcess.add(parent);
        pagesToProcess.addAll(parent.getChildren());
        for (WikiPage eachPage : pagesToProcess) {
          changePageCommittedProperty(eachPage.getData(), eachPage, true);
        }
          /*
          String pagePath = ((WikiFilePage) eachPage).getFileSystemPath().getCanonicalPath() + ".wiki";
          Repository repository = new FileRepositoryBuilder().findGitDir(new File(pagePath)).build();
          Git git = new Git(repository);
          pagePath = ((WikiFilePage) eachPage).getFileSystemPath().getPath().replace("./", "") + ".wiki";
          git.add().addFilepattern(pagePath).call();
          Status status = git.status().call();
          if (status.getAdded().size() + status.getChanged().size() == 1) {
            git.commit().setMessage(user + " : " + eachPage.getFullPath()).call();
            context.recentChanges.updateRecentChanges(eachPage);
          } else {
            throw new Exception("No file was found to be eligible for commit.");
          }
        */
        String pagePath = ((WikiFilePage) parent).getFileSystemPath().getCanonicalPath() + ".wiki";
        Repository repository = new FileRepositoryBuilder().findGitDir(new File(pagePath)).build();
        Git git = new Git(repository);
        pagePath = ((WikiFilePage) parent).getFileSystemPath().getPath().replace("./", "");
        git.add().addFilepattern(pagePath + ".wiki").addFilepattern(pagePath).call();
        Status status = git.status().call();
        int addedSize = status.getAdded().size();
        int changedSize = status.getChanged().size();
        if (addedSize + changedSize > 0) {
          String commitString = String.format("Commit by %s (%s%s) : %s", user, (addedSize > 0 ? "added: " + addedSize : ""), (changedSize > 0 ? ", modified: " + changedSize : ""), parent.getFullPath());
          System.out.println(commitString);
          git.commit().setMessage(commitString).call();
        } else {
          throw new Exception("No file was found to be eligible for commit.");
        }
        redirect(path, simpleResponse);

      } catch (Exception ex) {
        for (WikiPage eachPage : pagesToProcess) {
          changePageCommittedProperty(eachPage.getData(), eachPage, false);
        }
        throw ex;
      }
    }
  }

  private void changePageCommittedProperty(PageData data, WikiPage page, boolean isCommitted) {
    data.setAttribute(PageData.PropertyCommitted, String.valueOf(isCommitted));
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


  private String buildConfirmationHtml(final WikiPage root, final String qualifiedPageName,
                                       final FitNesseContext context, Request request) {
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
    html.setMainTemplate("commitPage");
    return html.html(request);
  }

  private void makeMainContent(final HtmlPage html, final WikiPage root, final String qualifiedPageName) {
    WikiPagePath path = PathParser.parse(qualifiedPageName);
    WikiPage pageToCommit = root.getPageCrawler().getPage(path);
    List<WikiPage> children = pageToCommit.getChildren();

    html.put("commitSubPages", children != null && !children.isEmpty());
    html.put("pageName", qualifiedPageName);
  }

  @Override
  public SecureOperation getSecureOperation() {
    return new SecureWriteOperation();
  }
}
