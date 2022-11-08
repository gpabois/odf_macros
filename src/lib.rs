extern crate proc_macro;

use proc_macro::TokenStream;
use syn::{Expr, ExprArray};
use syn::{parse_macro_input, DeriveInput, parse::Parser, FieldsNamed, token::Token};
use quote::quote;
use proc_macro2::TokenStream as TokenStream2;

fn add_fields(fields: &mut FieldsNamed, tokens: &[TokenStream2])
{
    tokens.iter().for_each(|token| {
        fields.named.push(syn::Field::parse_named.parse2(token.clone()).unwrap())
    });
}

fn parse_types(args: TokenStream) -> Vec<syn::Ident>
{
    let ast = syn::parse(args).unwrap();
    let mut types: Vec<syn::Ident> = vec![];

    match &ast {
        Expr::Array(array) => {
            for el in array.elems.iter() {
                match el {
                    syn::Expr::Path(path) => {
                        types.push(path.path.segments.first().unwrap().ident.clone());
                    },
                    _ => {}
                }
            }
        },
        _ => {}
    }
    
    types
}

#[proc_macro_attribute]
pub fn define_child_elements(args: TokenStream, input: TokenStream) -> TokenStream
{
    let mut ast = parse_macro_input!(input as DeriveInput);
    let types: Vec<syn::Ident> = parse_types(args);

    match &mut ast {
        syn::Data::Struct(struct_data) => {
            struct_data.fields
        }
    }
    
    return quote! {
        #ast
    }.into();
}

#[proc_macro_attribute]
pub fn header_attrs(_args: TokenStream, input: TokenStream) -> TokenStream
{
    let mut struct_ast = parse_macro_input!(input as DeriveInput);
    
    match &mut struct_ast.data {
        syn::Data::Struct(ref mut struct_data) => {           
            match &mut struct_data.fields {
                syn::Fields::Named(fields) => {
                    add_fields(fields, &[
                        quote!{pub outline_level: u8},
                        quote!{pub restart_numbering: bool},
                        quote!{pub start_value: u8},
                        quote!{pub is_list_header: bool},
                        quote!{pub number: String}
                    ])
                }   
                _ => {
                    ()
                }
            }              
            
            return quote! {
                #ast
            }.into();
        }
        _ => panic!("`header_attrs` has to be used with structs "),
    }
}

#[proc_macro_attribute]
pub fn paragraph_attrs(_args: TokenStream, input: TokenStream) -> TokenStream
{
    let mut ast = parse_macro_input!(input as DeriveInput);
    match &mut ast.data {
        syn::Data::Struct(ref mut struct_data) => {           
            match &mut struct_data.fields {
                syn::Fields::Named(fields) => {
                    add_fields(
                        fields,
                        &[
                            quote!{pub style_name: Option<String>},
                            quote!{pub class_names: Option<String>},
                            quote!{pub cond_style_name: Option<String>},
                            quote!{pub id: Option<String>}
                        ]
                    )
                }   
                _ => {
                    ()
                }
            }              
            
            return quote! {
                #ast
            }.into();
        }
        _ => panic!("`paragraph_attrs` has to be used with structs "),
    }
}