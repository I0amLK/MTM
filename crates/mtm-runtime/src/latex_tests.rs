use super::*;

fn document(body: &str) -> String {
    format!(
        "\\documentclass{{article}}\n\\usepackage{{fancyvrb}}\n\\begin{{document}}\n{body}\n\\end{{document}}\n"
    )
}

#[test]
fn source_appendix_is_literal_not_another_document() -> Result<(), ReCtmError> {
    for environment in ["Verbatim", "Verbatim*", "verbatim", "verbatim*"] {
        let body = format!(
            "\\begin{{{environment}}}\n\\documentclass{{article}}\n\\begin{{document}}\n\\bibliography{{references}}\n\\end{{document}}\n% literal percent and unmatched brace {{\n\\end{{{environment}}}"
        );
        let errors = static_latex_errors(&document(&body))?;
        assert!(errors.is_empty(), "{environment}: {errors:?}");
    }
    Ok(())
}

#[test]
fn actual_file_loading_after_literal_appendix_remains_forbidden() -> Result<(), ReCtmError> {
    let errors = static_latex_errors(&document(
        "\\begin{Verbatim}\n\\input{example}\n\\end{Verbatim}\n\\bibliography{active}",
    ))?;
    assert!(
        errors
            .iter()
            .any(|error| error.ends_with("bibliography_file"))
    );
    Ok(())
}

#[test]
fn inline_literal_percent_braces_and_unicode_do_not_affect_the_outer_document()
-> Result<(), ReCtmError> {
    for body in [
        "\\verb|\\begin{document} % { \\input{literal}|",
        "\\verb*+\\end{document} } \\bibliography{literal}+",
        "中文 \\verb|数学 { % }| 正文",
        "\\begin{Verbatim}\r\n数学 { % \\input{literal}\r\n\\end{Verbatim}",
    ] {
        assert!(static_latex_errors(&document(body))?.is_empty(), "{body}");
    }
    Ok(())
}

#[test]
fn bounded_local_and_global_formatting_options_are_supported() -> Result<(), ReCtmError> {
    for body in [
        "\\begin{Verbatim}[fontsize=\\small,numbers=left,frame=single,numbersep=4pt]\n\\input{literal}\n\\end{Verbatim}",
        "\\fvset{fontsize=\\footnotesize,showspaces=false,tabsize=4}\n\\begin{Verbatim}\n{\n\\end{Verbatim}",
    ] {
        assert!(static_latex_errors(&document(body))?.is_empty(), "{body}");
    }
    Ok(())
}

#[test]
fn every_active_forbidden_operation_is_still_checked_on_both_sides() -> Result<(), ReCtmError> {
    let literal = "\\begin{Verbatim}\n\\input{literal}\n\\end{Verbatim}";
    for (operation, category) in [
        ("\\write18{payload}", "shell_escape"),
        ("\\input{active}", "input"),
        ("\\openout1=file", "file_write"),
        ("\\openin1=file", "file_read"),
        ("\\usepackage{shellesc}", "shellesc_package"),
        ("\\bibliography{active}", "bibliography_file"),
        ("\\includegraphics{active}", "external_graphic"),
        ("\\lstinputlisting{active}", "external_listing"),
        ("\\externaldocument{active}", "external_auxiliary"),
    ] {
        for body in [
            format!("{operation}\n{literal}"),
            format!("{literal}\n{operation}"),
        ] {
            let errors = static_latex_errors(&document(&body))?;
            assert!(
                errors.contains(&format!("forbidden LaTeX operation: {category}")),
                "{operation}: {errors:?}"
            );
        }
    }
    Ok(())
}

#[test]
fn first_raw_terminator_never_hides_following_active_text() -> Result<(), ReCtmError> {
    for environment in ["verbatim", "Verbatim"] {
        for prefix in ["", "%", "\\", "literal "] {
            let body = format!(
                "\\begin{{{environment}}}\n{prefix}\\end{{{environment}}}\\input{{active}}\n\\end{{{environment}}}"
            );
            assert!(
                static_latex_errors(&document(&body))?
                    .iter()
                    .any(|e| e.ends_with(": input")),
                "{body}"
            );
        }
    }
    Ok(())
}

#[test]
fn malformed_or_executable_literal_configurations_fail_closed() -> Result<(), ReCtmError> {
    for body in [
        "\\begin{Verbatim}\nunterminated",
        "\\verb|unterminated\n",
        "\\begin{Verbatim}[commandchars=\\\\\\{\\}]\n\\input{active}\n\\end{Verbatim}",
        "\\begin{Verbatim}[formatcom=\\input{active}]\ntext\n\\end{Verbatim}",
        "\\begin{Verbatim}[unknown=true]\ntext\n\\end{Verbatim}",
        "\\fvset{codes=\\relax}\n\\begin{Verbatim}\ntext\n\\end{Verbatim}",
        "\\setkeys{FV}{commandchars=![]}\n\\begin{Verbatim}\n!input[active]\n\\end{Verbatim}",
        "\\makeatletter\n\\begin{Verbatim}\ntext\n\\end{Verbatim}",
        "\\renewenvironment{Verbatim}{}{}\n\\begin{Verbatim}\ntext\n\\end{Verbatim}",
        "{\\verb|\\input{active}|}",
        "\\iffalse\n\\begin{Verbatim}\n\\fi\\input{active}\n\\end{Verbatim}",
        "\\catcode`!=0\n\\begin{Verbatim}\ntext\n\\end{Verbatim}",
        "^^5cinput{active}\n\\begin{Verbatim}\ntext\n\\end{Verbatim}",
    ] {
        assert!(!static_latex_errors(&document(body))?.is_empty(), "{body}");
    }
    Ok(())
}

#[test]
fn escaped_fake_begin_and_comments_cannot_mask_active_commands() -> Result<(), ReCtmError> {
    let body = "\\\\begin{Verbatim}\n\\input{active}\n\\end{Verbatim}";
    assert!(
        static_latex_errors(&document(body))?
            .iter()
            .any(|e| e.ends_with(": input"))
    );
    let body = "% \\begin{Verbatim}\n\\bibliography{active}\n% \\end{Verbatim}";
    assert!(
        static_latex_errors(&document(body))?
            .iter()
            .any(|e| e.ends_with("bibliography_file"))
    );
    Ok(())
}

#[test]
fn source_and_options_bounds_fail_before_unbounded_work() -> Result<(), ReCtmError> {
    assert_eq!(
        static_latex_errors(&"x".repeat(2 * 1024 * 1024 + 1))?,
        vec!["proof.tex exceeds the 2 MiB source limit"]
    );
    let body = format!(
        "\\begin{{Verbatim}}[{}]\nx\n\\end{{Verbatim}}",
        " ".repeat(4097)
    );
    assert!(!static_latex_errors(&document(&body))?.is_empty());
    Ok(())
}

#[test]
fn compiler_fixture_passes_the_same_static_gate() -> Result<(), ReCtmError> {
    let source = include_str!("../tests/fixtures/verbatim-appendix.tex");
    assert!(static_latex_errors(source)?.is_empty());
    Ok(())
}

#[test]
fn tex_control_words_end_at_digits_but_not_more_letters() -> Result<(), ReCtmError> {
    for (operation, category) in [
        ("\\openout1=file", "file_write"),
        ("\\openin1=file", "file_read"),
        ("\\write16{message}", "file_write"),
        ("\\input0.tex", "input"),
    ] {
        assert!(
            static_latex_errors(&document(operation))?
                .contains(&format!("forbidden LaTeX operation: {category}"))
        );
    }
    assert!(static_latex_errors(&document("\\inputexample \\openoutput \\readable"))?.is_empty());
    Ok(())
}

#[test]
fn literal_configuration_restrictions_do_not_expand_to_documents_without_literals()
-> Result<(), ReCtmError> {
    assert!(static_latex_errors(&document("\\fvset{formatcom=\\relax} ordinary text"))?.is_empty());
    assert!(
        static_latex_errors(&document(
            "\\fvset{formatcom=\\input{active}} ordinary text"
        ))?
        .iter()
        .any(|e| e.ends_with(": input"))
    );
    Ok(())
}
