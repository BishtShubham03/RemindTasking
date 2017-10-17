from jinja2 import Template


def render_template(content, argument_dictionary):
    template = Template(content)

    rendered_html_data = template.render(argument_dictionary)

    return rendered_html_data
