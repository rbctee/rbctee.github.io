# Blog

## Serving

```bash
bundle exec jekyll serve --watch --drafts
```

## GitHub Pages

To build for GitHub pages (when using custom plugins):

```bash
# install jgd
sudo gem install jgd

# build and push remotely
# the argument `-n` specifies to jgd to use bundle when building the pages
jgd -n
```

P.S. You have to serve the content from the branch `gh-pages`.
