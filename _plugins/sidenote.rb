module Jekyll
  class RenderSideNoteTag < Liquid::Tag

    require "shellwords"

    def initialize(tag_name, text, tokens)
      super
      @text = text
    end

    def render(context)
      "{::nomarkdown}<p>{:/}<sub class='aside'>#{@text}</sub>{::nomarkdown}</p>{:/}"
    end
  end
end

Liquid::Template.register_tag('sidenote', Jekyll::RenderSideNoteTag)

