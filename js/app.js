// TBH, I am complete novice at JS, JQuery, AJAX.
// This code might be messy, but at least I got it to work

$(document).foundation();

$("button[name=showMore]")
    .click(
       function () {
           $(this).hide();
        }
    );

$("body").on("click", "button[name=editComment]", function() {
      // Shows comment edit form and passes text to textarea
      $comment = $(this).parent().parent();
      $textarea = $comment.find(".comment__text");
      $commit = $comment.find(".comment__commit");
      $discard = $comment.find(".comment__discard");
      $editarea = $comment.find(".comment__editarea");
      text = $textarea.text();
      $editarea.text(text);
      $textarea.hide();
      $commit.show();
      $discard.show();
      $editarea.show();
});

$("body").on("click", "button[name=comment__discard]", function () {
      // discard changes, brings back normal comment view
      $comment = $(this).parent().parent().parent().parent();
      /*I got to admit, this looks lame here*/
      $comment.find(".comment__editarea").hide();
      $comment.find(".comment__discard").hide();
      $comment.find(".comment__commit").hide();
      $comment.find(".comment__text").show();
});

function Like(blog_key) {
  $.ajax({
        type: "POST",
        url: "/like",
        dataType: "json",
        data: JSON.stringify({"blog_key": blog_key})
    })
        .done(function (data) {
            var id = data.blog_key;
          $("#" + id).find(".likes__counter").text(data.likes);
        });
}

function Comment(content, blog_key) {
  $.ajax({
        type: "POST",
        url: "/comment",
        dataType: "json",
        data: JSON.stringify({"content": content, "blog_key": blog_key})
    })
        .done(function (data) {
            $(".comment__new").append(data.comment);
        });
}

function DeleteComment(comment_key) {
  $.ajax({
        type: "POST",
        url: "/comment",
        dataType: "json",
        data: JSON.stringify({"comment_key": comment_key})
    })
        .done(function (data) {
            var id = data.comment_key;
            $("#" + id).hide();
        });
}

function EditComment(content, comment_key) {
  $.ajax({
        type: "POST",
        url: "/comment",
        dataType: "json",
        data: JSON.stringify({"content": content, "comment_key": comment_key})
    })
        .done(function (data) {
            var id = data.comment_key;
            $("#" + id).find(".comment__editarea").hide();
            $("#" + id).find(".comment__discard").hide();
            $("#" + id).find(".comment__commit").hide();
            $("#" + id).find(".comment__text").text(data.content);
            $("#" + id).find(".comment__text").show();
        });
}