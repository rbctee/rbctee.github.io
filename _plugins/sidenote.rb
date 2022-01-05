module Jekyll
  class RenderSideNoteTag < Liquid::Tag

    require "shellwords"

    def initialize(tag_name, text, tokens)
      super
      @text = text
    end

    def render(context)
      site = context.registers[:site]
      converter = site.find_converter_instance(::Jekyll::Converters::Markdown)
      text = Kramdown::Document.new(@text,{}).to_html # render markdown in caption
      temp = "<sub class='aside'>#{converter.convert(@text)}</sub>"
      # temp = "{::nomarkdown}" + converter.convert("<p>{:/}<sub class='aside'>#{(@text)}</sub>{::nomarkdown}</p>{:/}")
      # converter.convert(temp)
      temp.sub! "<sub class='aside'><p>", "<sub class='aside'>"
      temp.sub! "</p>", ""
    end
  end
end

Liquid::Template.register_tag('sidenote', Jekyll::RenderSideNoteTag)

